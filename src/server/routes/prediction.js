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
 * Get a prediction result content
 */
router.get('/:predictionId/attack', (req, res, next) => {
  const { predictionId } = req.params;
  const predictionFilePath = `${PREDICTION_PATH}${predictionId}/attacks.csv`;
  isFileExist(predictionFilePath, (ret) => {
    if (!ret) {
      res.status(401).send(`The prediction file for attack traffic of ${predictionId} does not exist`);
    } else {
      res.sendFile(predictionFilePath);
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

  // Check if prediction is still running
  const session = sessionManager.getSession('prediction', predictionId);

  if (session && session.isRunning) {
    return res.status(202).json({
      status: 'processing',
      message: 'Prediction is still in progress',
      predictionId: predictionId,
      startedAt: session.createdAt
    });
  }

  readTextFile(`${PREDICTION_PATH}${predictionId}/stats.csv`, (err, prediction) => {
    if (err) {
      // Check if the prediction directory exists
      const fs = require('fs');
      const path = require('path');
      const predictionDir = path.join(PREDICTION_PATH, predictionId);

      if (!fs.existsSync(predictionDir)) {
        return res.status(404).json({
          error: 'Prediction not found',
          message: `No prediction found with ID: ${predictionId}`
        });
      }

      // Directory exists but stats.csv doesn't - likely still processing or failed
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
