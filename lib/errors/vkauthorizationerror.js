/**
 * @constructor
 * @param {String} [message]
 * @param {Number} [code]
 * @api public
 */
function VKAuthorizationError(message, code) {
  Error.call(this);
  Error.captureStackTrace(this, arguments.callee);
  this.name = 'FacebookAuthorizationError';
  this.message = message;
  this.code = code;
  this.status = 500;
}

/**
 * Inherit from `Error`.
 */
VKAuthorizationError.prototype.__proto__ = Error.prototype;


/**
 * Expose `FacebookAuthorizationError`.
 */
module.exports = VKAuthorizationError;
