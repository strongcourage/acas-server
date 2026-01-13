const express = require('express');
const {
  getPredictingStatus,
  startPredicting,
  stopOnlinePrediction,
} = require('../deep-learning/deep-learning-connector');
const { listNetworkInterfaces } = require('../utils/utils');
const { queuePrediction, getJobStatus } = require('../queue/job-queue');
const { handleQueueError, isRedisError } = require('../utils/queueErrorHelper');
const { v4: uuidv4 } = require('uuid');

const router = express.Router();

router.get('/stop', (req, res) => {
  stopOnlinePrediction((predictingStatus) => {
    res.send({
      predictingStatus,
    });
  });

});
/**
 * Use a selectedModel (modelId) to classify an input traffic
 * The input traffic can be from a pcap file, a dataset or a network interface
 * Example of the predictConfig
 * - Analyze a pcap file
 * {
 *  selectedModel: 'model-001',
 *  inputTraffic: {
 *    type: 'pcapFile',
 *    value: 'my-pcap-file.pcap'
 *  }
 * }
 * - Analyze a dataset
 * {
 *  selectedModel: 'model-001',
 *  inputTraffic: {
 *    type: 'dataset',
 *    value: 'my-dataset-01'
 *  }
 * }
 * - Analyze a live traffic
 * {
 *  selectedModel: 'model-001',
 *  inputTraffic: {
 *    type: 'net',
 *    value: 'eth0'
 *  }
 * }
 */
router.post('/', async (req, res) => {
  const {
    predictConfig,
  } = req.body;
  if (!predictConfig) {
    res.status(401).send({
      error: 'Missing predicting configuration. Please read the docs',
    });
  } else {
    startPredicting(predictConfig, (predictingStatus) => {
      res.send(predictingStatus);
    });
  }
});

router.get('/', (req, res) => {
  res.send({
    predictingStatus: getPredictingStatus(),
  });
});

router.get('/interfaces', (req, res) => {
  const networkInterfaces = listNetworkInterfaces();
  const ipv4Addresses = Object.keys(networkInterfaces).reduce((addresses, interfaceName) => {
    const ipv4Interface = networkInterfaces[interfaceName].find((interface) => interface.family === 'IPv4');

    if (ipv4Interface) {
      addresses.push(`${interfaceName} - ${ipv4Interface.address}`);
    }

    return addresses;
  }, []);

  console.log(ipv4Addresses);

  res.send({
    interfaces: ipv4Addresses,
  });
});

/**
 * POST /api/predict/offline
 * Queue-based offline prediction (non-blocking)
 * Body: { modelId: string, reportId: string, reportFileName: string, useQueue?: boolean }
 */
router.post('/offline', async (req, res) => {
  try {
    const { modelId, reportId, reportFileName, useQueue } = req.body || {};

    if (!modelId || !reportId || !reportFileName) {
      return res.status(400).json({
        error: 'Missing required parameters',
        message: 'modelId, reportId, and reportFileName are required'
      });
    }

    // Queue-based approach is ENABLED BY DEFAULT
    const useQueueDefault = process.env.USE_QUEUE_BY_DEFAULT !== 'false';
    const shouldUseQueue = useQueue !== undefined ? useQueue : useQueueDefault;
    let fallbackToSync = false;

    if (shouldUseQueue) {
      console.log('[Prediction] Using queue-based processing for model:', modelId);

      // Generate unique prediction ID
      const predictionId = `predict-${Date.now()}-${uuidv4().substring(0, 8)}`;

      let jobInfo;
      try {
        // Queue the prediction job
        jobInfo = await queuePrediction({
          modelId,
          reportId,
          reportFileName,
          predictionId,
          priority: 5
        });
        
        return res.json({
          success: true,
          useQueue: true,
          predictionId,
          jobId: jobInfo.jobId,
          queueName: jobInfo.queueName,
          position: jobInfo.position,
          estimatedWait: jobInfo.estimatedWait,
          message: 'Prediction job queued successfully'
        });
      } catch (error) {
        // Check if it's a Redis connection error
        if (isRedisError(error)) {
          console.warn('[Prediction] Redis unavailable, automatically falling back to sync mode');
          fallbackToSync = true;
          // Fall through to sync processing below
        } else {
          // For non-Redis errors, return the error
          return handleQueueError(res, error, 'Prediction queue');
        }
      }
    }

    // Direct processing (blocking) - used when useQueue=false OR when Redis is unavailable
    console.log('[Prediction] Using direct processing (blocking) for model:', modelId);

    // Use existing direct prediction method (legacy)
    const predictConfig = {
      modelId,
      inputTraffic: {
        type: 'report',
        value: { reportId, reportFileName }
      }
    };

    startPredicting(predictConfig, (predictingStatus) => {
      if (predictingStatus.error) {
        return res.status(500).json({
          success: false,
          error: predictingStatus.error
        });
      }

      const response = {
        success: true,
        useQueue: false,
        predictionId: predictingStatus.lastPredictedId,
        ...predictingStatus,
        message: fallbackToSync 
          ? 'Prediction started in sync mode (Redis unavailable, automatic fallback)' 
          : 'Prediction started (blocking mode)'
      };

      if (fallbackToSync) {
        response.warning = 'Redis/Valkey service is unavailable. Automatically switched to synchronous processing mode.';
      }

      res.json(response);
    });

  } catch (error) {
    console.error('[Prediction] Error:', error);
    res.status(500).json({
      error: 'Internal server error',
      message: error.message
    });
  }
});

/**
 * GET /api/predict/job/:jobId
 * Get status of a queued prediction job
 */
router.get('/job/:jobId', async (req, res) => {
  try {
    const { jobId } = req.params;
    const status = await getJobStatus(jobId, 'prediction');
    res.json(status);
  } catch (error) {
    res.status(500).json({
      error: 'Failed to get job status',
      message: error.message
    });
  }
});

module.exports = router;
