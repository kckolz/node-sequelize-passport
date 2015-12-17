var express = require('express'),
    router  = express.Router();

router.get('/test', function(req, res) {
  res.send("Hello Planet");
});

module.exports = router;