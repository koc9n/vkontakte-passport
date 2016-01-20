# vkontakte-passport

This module lets you authenticate using VKontakte OAuth 2.0 in your Node.js applications.
Added for using passport authentication with VKontakte strategy.

## Usage
By example to use this plugin in own sails project you should add some of this to 
*config -> passport.js*

      vkontakte: {
            name: 'Vkontakte',
            protocol: 'oauth2',
            strategy: require('vkontakte-passport').Strategy,
            options: {
                  clientID: 'your_app_id',
                  clientSecret: 'your_client_secret',
                  scope: ['email'],
                  profileFields: ['screen_name','domain','photo_200_orig','sex','middle_name'], // by example I used this fields
                  callbackURL: 'http://{your_ip_or_domain}/auth/vkontakte/callback'
            }
      }
      
### Note 1
You need to change your *services -> passport.js*
to set to your User model needed profile fields.

### Note 2
You can generate basic passport auth structure for sails app using sails-generate-auth module.
                
    npm install sails-generate-auth
    
see instruction of usage [here](https://www.npmjs.com/package/sails-generate-auth)

    
## Install

    $ npm install vkontakte-passport





