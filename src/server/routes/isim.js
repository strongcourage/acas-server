/**
 * ISIM Integration Routes
 *
 * Proxy endpoints to communicate with ISIM (Inventory / Scanning & Information Management)
 * for asset criticality information.
 *
 * ISIM provides:
 * - IP addresses of assets
 * - Criticality scores
 * - Mission assignments
 * - Services and vulnerabilities
 */

const express = require('express');
const router = express.Router();
const { ISIM_URL } = require('../constants');

/**
 * GET /api/isim/status
 * Check ISIM connectivity
 */
router.get('/status', async (req, res) => {
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 5000);

    const response = await fetch(`${ISIM_URL}/asset_info?limit=1`, {
      signal: controller.signal
    });
    clearTimeout(timeout);

    res.json({
      connected: response.ok,
      url: ISIM_URL,
      status: response.status
    });
  } catch (error) {
    res.json({
      connected: false,
      url: ISIM_URL,
      error: error.message
    });
  }
});

/**
 * GET /api/isim/asset_info
 * Proxy to ISIM /asset_info endpoint
 *
 * Query params:
 * - limit: Number of results (default: 50)
 * - offset: Pagination offset (default: 0)
 * - ip: Filter by specific IP (optional)
 *
 * Response format from ISIM:
 * [
 *   {
 *     "ip": "10.0.0.5",
 *     "domain_names": ["server.example.com"],
 *     "subnets": ["10.0.0.0/16"],
 *     "contacts": ["admin@example.com"],
 *     "missions": ["Production Database"],
 *     "nodes": [{ "degree_centrality": 1.0, "pagerank_centrality": 0.15 }],
 *     "critical": 1
 *   }
 * ]
 */
router.get('/asset_info', async (req, res) => {
  try {
    const { limit = 50, offset = 0, ip } = req.query;
    let url = `${ISIM_URL}/asset_info?limit=${limit}&offset=${offset}`;
    if (ip) {
      url += `&ip=${encodeURIComponent(ip)}`;
    }

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10000);

    const response = await fetch(url, {
      signal: controller.signal
    });
    clearTimeout(timeout);

    if (!response.ok) {
      return res.status(response.status).json({
        error: 'ISIM request failed',
        status: response.status
      });
    }

    const data = await response.json();
    res.json(data);
  } catch (error) {
    console.error('[ISIM] Error fetching asset_info:', error.message);
    res.status(500).json({
      error: 'Failed to fetch from ISIM',
      message: error.message
    });
  }
});

/**
 * GET /api/isim/assets/critical
 * Get only critical assets (critical=1)
 */
router.get('/assets/critical', async (req, res) => {
  try {
    const { limit = 1000 } = req.query;

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10000);

    const response = await fetch(`${ISIM_URL}/asset_info?limit=${limit}`, {
      signal: controller.signal
    });
    clearTimeout(timeout);

    if (!response.ok) {
      return res.status(response.status).json({
        error: 'ISIM request failed',
        status: response.status
      });
    }

    const data = await response.json();
    const criticalAssets = data.filter(asset => asset.critical === 1);

    res.json({
      total: data.length,
      critical: criticalAssets.length,
      assets: criticalAssets
    });
  } catch (error) {
    console.error('[ISIM] Error fetching critical assets:', error.message);
    res.status(500).json({
      error: 'Failed to fetch critical assets from ISIM',
      message: error.message
    });
  }
});

/**
 * GET /api/isim/assets/:ip
 * Get information for a specific IP
 */
router.get('/assets/:ip', async (req, res) => {
  try {
    const { ip } = req.params;

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 5000);

    const response = await fetch(`${ISIM_URL}/asset_info?ip=${encodeURIComponent(ip)}`, {
      signal: controller.signal
    });
    clearTimeout(timeout);

    if (!response.ok) {
      return res.status(response.status).json({
        error: 'ISIM request failed',
        status: response.status
      });
    }

    const data = await response.json();

    if (!data || data.length === 0) {
      return res.status(404).json({
        error: 'Asset not found',
        ip: ip
      });
    }

    res.json(data[0]);
  } catch (error) {
    console.error(`[ISIM] Error fetching asset ${req.params.ip}:`, error.message);
    res.status(500).json({
      error: 'Failed to fetch asset from ISIM',
      message: error.message
    });
  }
});

/**
 * POST /api/isim/enrich
 * Enrich a list of IPs with ISIM context
 *
 * Body: { "ips": ["10.0.0.5", "10.0.0.6"] }
 *
 * Returns: Map of IP -> ISIM info
 */
router.post('/enrich', async (req, res) => {
  try {
    const { ips } = req.body;

    if (!ips || !Array.isArray(ips)) {
      return res.status(400).json({
        error: 'Invalid request',
        message: 'Request body must contain "ips" array'
      });
    }

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 15000);

    // Fetch all assets (or a large batch)
    const response = await fetch(`${ISIM_URL}/asset_info?limit=10000`, {
      signal: controller.signal
    });
    clearTimeout(timeout);

    if (!response.ok) {
      return res.status(response.status).json({
        error: 'ISIM request failed',
        status: response.status
      });
    }

    const allAssets = await response.json();

    // Create lookup map
    const assetMap = {};
    allAssets.forEach(asset => {
      assetMap[asset.ip] = asset;
    });

    // Enrich requested IPs
    const enriched = {};
    ips.forEach(ip => {
      enriched[ip] = assetMap[ip] || null;
    });

    res.json({
      total: ips.length,
      found: Object.values(enriched).filter(v => v !== null).length,
      assets: enriched
    });
  } catch (error) {
    console.error('[ISIM] Error enriching IPs:', error.message);
    res.status(500).json({
      error: 'Failed to enrich IPs with ISIM data',
      message: error.message
    });
  }
});

module.exports = router;
