'use strict';

const { validationResult } = require('express-validator');

function validate(validations) {
  return async (req, res, next) => {
    try {
      for (const validation of validations) {
        await validation.run(req);
      }

      const result = validationResult(req);
      if (result.isEmpty()) {
        return next();
      }

      const errors = result.array().map((err) => ({
        field: err.path || err.param,
        message: err.msg,
      }));

      return res.status(400).json({ errors });
    } catch (error) {
      return next(error);
    }
  };
}

module.exports = {
  validate,
};
