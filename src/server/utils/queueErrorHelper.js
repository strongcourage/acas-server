/**
 * Helper to handle queue-related errors consistently across routes
 */

function handleQueueError(res, error, operation = 'Background job processing') {
  console.error(`[Queue Error] ${operation}:`, error.message);

  const isRedisError = error.message.includes('Redis') ||
    error.message.includes('ECONNREFUSED') ||
    error.message.includes('Connection refused') ||
    error.message.includes('Stream isn\'t writeable') ||
    error.message.includes('enableOfflineQueue');

  if (isRedisError) {
    return res.status(503).json({
      error: 'Queue service (Redis) unavailable',
      message: `${operation} is currently unavailable because the Redis/Valkey service is not running.`,
      suggestion: 'Please ensure Redis/Valkey is running on your system, or set "useQueue": false in your request body for direct (non-queued) processing.',
      details: error.message
    });
  }

  // For other errors, return a standard 500 error
  return res.status(500).json({
    error: `${operation} failed`,
    message: error.message || 'An internal error occurred while queuing the job'
  });
}

module.exports = {
  handleQueueError
};
