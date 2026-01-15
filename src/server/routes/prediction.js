/* eslint-disable no-unused-vars */
const express = require('express');

const router = express.Router();
const {
  PREDICTION_PATH,
} = require('../constants');
const {
  listFiles, readTextFile, isFileExist,
} = require('../utils/file-utils');

/** Download a prediction .csv file */
router.get('/:predictionId/download', (req, res, next) => {
  const { predictionId } = req.params;
  const predictionFilePath = `${PREDICTION_PATH}${predictionId}/predictions.csv`;
  isFileExist(predictionFilePath, (ret) => {
    if (!ret) {
      res.status(401).send(`The prediction file of ${predictionId} does not exist`);
    } else {
      res.sendFile(predictionFilePath);
    }
  });
});

/**
 * Get a prediction result content (singular - returns CSV file)
 */
router.get('/:predictionId/attack', (req, res, next) => {
  const { predictionId } = req.params;
  const sessionManager = require('../utils/sessionManager');
  const session = sessionManager.getSession('prediction', predictionId);
  
  // Disable caching for online predictions (files are continuously updated)
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');

  // For online mode, allow reading files even while running (they're continuously updated)
  // For offline mode, wait until completion
  const isOnlineMode = session?.mode === 'online';
  if (session && session.isRunning && !isOnlineMode) {
    return res.status(202).send('Prediction is still in progress, attacks file not yet available');
  }

  const predictionFilePath = `${PREDICTION_PATH}${predictionId}/attacks.csv`;
  isFileExist(predictionFilePath, (ret) => {
    if (!ret) {
      // Prediction completed but no attacks file (all flows were normal)
      // Return empty CSV with just a header so client can parse it
      res.setHeader('Content-Type', 'text/csv');
      res.status(200).send(''); // Empty CSV = no attacks
    } else {
      res.sendFile(predictionFilePath);
    }
  });
});

/**
 * Get attacks as JSON (plural - for backward compatibility)
 * Returns 202 if prediction still running, 404 if not found
 */
router.get('/:predictionId/attacks', (req, res, next) => {
  const { predictionId } = req.params;
  const sessionManager = require('../utils/sessionManager');
  const session = sessionManager.getSession('prediction', predictionId);

  // If prediction is still running, return 202
  if (session && session.isRunning) {
    return res.status(202).json({
      status: 'processing',
      message: 'Prediction is still in progress, attacks file not yet available'
    });
  }

  const predictionFilePath = `${PREDICTION_PATH}${predictionId}/attacks.csv`;
  isFileExist(predictionFilePath, (ret) => {
    if (!ret) {
      // Prediction completed but no attacks file - return empty
      return res.status(200).json({
        attacks: null,
        message: 'No attacks detected or file not generated'
      });
    } else {
      readTextFile(predictionFilePath, (err, content) => {
        if (err) {
          return res.status(500).json({
            error: 'Failed to read attacks file',
            attacks: null
          });
        }
        res.json({ attacks: content });
      });
    }
  });
});

/**
 * Get a prediction result content
 */
router.get('/:predictionId/normal', (req, res, next) => {
  const { predictionId } = req.params;
  const predictionFilePath = `${PREDICTION_PATH}${predictionId}/normals.csv`;
  isFileExist(predictionFilePath, (ret) => {
    if (!ret) {
      res.status(401).send(`The prediction file for normal traffic of ${predictionId} does not exist`);
    } else {
      res.sendFile(predictionFilePath);
    }
  });
});

// /**
//  * Get a prediction result content
//  */
// router.get('/:predictionId/all', (req, res, next) => {
//   const { predictionId } = req.params;
//   readTextFile(`${PREDICTION_PATH}${predictionId}/predictions.csv`, (err, content) => {
//     if (err) {
//       res.status(401).send({ error: 'Something went wrong!' });
//     } else {
//       res.send({ content });
//     }
//   });
// });

/**
 * Get a prediction result content
 */
router.get('/:predictionId', (req, res, next) => {
  const { predictionId } = req.params;
  const sessionManager = require('../utils/sessionManager');
  
  // Disable caching for online predictions (stats.csv is continuously updated)
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');

  // Check if prediction is still running
  const session = sessionManager.getSession('prediction', predictionId);
  
  // For online mode, allow reading stats even while running (they're continuously updated)
  // For offline mode, wait until completion
  const isOnlineMode = session?.mode === 'online';
  if (session && session.isRunning && !isOnlineMode) {
    return res.status(202).json({
      status: 'processing',
      message: 'Prediction is still in progress',
      predictionId: predictionId,
      startedAt: session.createdAt
    });
  }

  // Use fs.readFile directly to avoid logging ENOENT errors for online mode
  const fs = require('fs');
  const path = require('path');
  const statsPath = path.join(PREDICTION_PATH, predictionId, 'stats.csv');
  
  fs.readFile(statsPath, 'utf8', (err, prediction) => {
    if (err) {
      // Check if the prediction directory exists
      const predictionDir = path.join(PREDICTION_PATH, predictionId);

      if (!fs.existsSync(predictionDir)) {
        return res.status(404).json({
          error: 'Prediction not found',
          message: `No prediction found with ID: ${predictionId}`
        });
      }

      // Directory exists but stats.csv doesn't
      // For online mode, return empty stats (no predictions completed yet) - don't log error
      // For offline mode, this is an error - log it
      if (isOnlineMode) {
        return res.send({ prediction: '0,0,0' }); // No flows yet
      }
      
      // Log error for offline mode only
      console.error(`[Prediction Stats] Error reading stats.csv for ${predictionId}:`, err.message);
      
      if (session && !session.isRunning) {
        return res.status(500).json({
          error: 'Prediction failed',
          message: 'The prediction process completed but did not generate results. Check the prediction logs.',
          predictionId: predictionId
        });
      }

      return res.status(404).json({
        error: 'Results not available',
        message: 'Prediction results file (stats.csv) not found. The prediction may still be processing or may have failed.',
        predictionId: predictionId
      });
    } else {
      res.send({ prediction });
    }
  });
});

/**
 * Get all prediction result list
 */
router.get('/', (req, res, next) => {
  listFiles(PREDICTION_PATH, '*', (files) => {
    res.send({
      predictions: files,
    });
  });
});


module.exports = router;
