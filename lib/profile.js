/**
 * Parse profile.
 *
 * @param {Object|String} json
 * @return {Object}
 * @api private
 */
exports.parse = function (json) {
    if ('string' == typeof json) {
        json = JSON.parse(json);
    }

    var profile = {};

    // fill original retrieved fields from vk account to profile
    var jsonFields = Object.keys(json);
    for (var key in jsonFields) {
        profile[jsonFields[key]] = json[jsonFields[key]];
    }

    // fill the basic fields for profile
    profile.id = json.uid;
    profile.username = json.screen_name;
    profile.displayName = json.screen_name;
    profile.name = {
        familyName: json.last_name,
        givenName: json.first_name,
        middleName: json.middle_name
    };

    profile.gender = json.sex;
    profile.profileUrl = 'https://vk.com/' + json.domain;

    profile.photos = [{value: json.photo_200_orig}];

    return profile;
};
