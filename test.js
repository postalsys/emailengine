
import('matcher').then(({matcher, isMatch}) => {

  var wildcard = require('wildcard');

  let rules = ['*wws.neti.ee/*', '*.neti.ee/*', 'https://www.neti.ee/*'];

  var testdata = 'https://www.neti.ee/cgi-bin/teema/HARIDUS_JA_KULTUUR/Haridus/Oppematerjalid/'
   
  for(let rule of rules){
      console.log(rule, isMatch(testdata, rule));
  }

});