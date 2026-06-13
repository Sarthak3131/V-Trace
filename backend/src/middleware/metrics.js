'use strict';

const requestCounts = {};
const statusCounts = {};
const responseTimes = {};
let totalRequests = 0;
let totalErrors = 0;
const rollingResponseTimes = [];

function metricsMiddleware(req, res, next) {
  const start = process.hrtime();
  totalRequests++;

  res.on('finish', () => {
    const duration = process.hrtime(start);
    const ms = duration[0] * 1000 + duration[1] / 1000000;

    const route = `${req.method} ${req.baseUrl}${req.route ? req.route.path : req.path}`;
    const statusCode = res.statusCode;

    // Track status code counts
    statusCounts[statusCode] = (statusCounts[statusCode] || 0) + 1;
    if (statusCode >= 400) {
      totalErrors++;
    }

    // Track request count by route
    requestCounts[route] = (requestCounts[route] || 0) + 1;

    // Track response times by route
    if (!responseTimes[route]) {
      responseTimes[route] = {
        count: 0,
        totalMs: 0,
        maxMs: 0,
        avgMs: 0,
      };
    }
    const rt = responseTimes[route];
    rt.count++;
    rt.totalMs += ms;
    if (ms > rt.maxMs) rt.maxMs = ms;
    rt.avgMs = rt.totalMs / rt.count;

    // Keep rolling response times history up to 1000 requests
    rollingResponseTimes.push(ms);
    if (rollingResponseTimes.length > 1000) {
      rollingResponseTimes.shift();
    }
  });

  next();
}

function getMetricsData() {
  const avgResponseTime = rollingResponseTimes.length > 0
    ? rollingResponseTimes.reduce((a, b) => a + b, 0) / rollingResponseTimes.length
    : 0;

  const routeBreakdown = Object.keys(requestCounts).map(route => ({
    route,
    count: requestCounts[route],
    avgResponseTimeMs: parseFloat(responseTimes[route].avgMs.toFixed(2)),
    maxResponseTimeMs: parseFloat(responseTimes[route].maxMs.toFixed(2)),
  })).sort((a, b) => b.count - a.count);

  return {
    totalRequests,
    totalErrors,
    avgResponseTimeMs: parseFloat(avgResponseTime.toFixed(2)),
    statusCounts,
    routeBreakdown,
  };
}

module.exports = {
  metricsMiddleware,
  getMetricsData,
};
