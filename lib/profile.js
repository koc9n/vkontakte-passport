/**
 * Parse profile.
 *
 * @param {Object|String} json
 * @return {Object}
 * @api private
 */
exports.parse = function(json) {
  if ('string' == typeof json) {
    json = JSON.parse(json);
  }
  var profile = {};
  profile.id = json.uid;
  profile.username = json.screen_name;
  profile.displayName = json.screen_name;
  profile.name = { familyName: json.last_name,
                   givenName: json.first_name,
                   middleName: json.middle_name };

  profile.gender = json.sex;
  profile.profileUrl = 'vk.com/' + json.domain;
  
  if (json.email) {
    profile.email = json.email;
    profile.emails = [{ value: json.email }];
  }
  
  profile.photos = [{ value: json.photo_200_orig }];
  
  return profile;
};