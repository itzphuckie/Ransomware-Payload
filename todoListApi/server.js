var express = require('express'),
        app = express(),
        port = process.env.PORT || 3000
        mongoose = require('mongoose'),
        Task = require('./api/models/todoListModel'), //created model loading here
        bodyParser = require('body-parser'),
        config = require('./config');
// mongoose instance connection url connection
mongoose.Promise = global.Promise;
//mongoose.connect('mongodb://xyzescure.me/Tododb');
mongoose.connect(config.database);
//mongoose.connect('mongodb://localhost/Tododb');

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

app.get('/', function(req,res){

        res.send('Welcome to XYZsecureMe ! You are protected. SIKE! ');
});

var routes = require('./api/routes/todoListRoutes'); //importing route
routes(app); //register the route
app.listen(port);

//testing connectivity
mongoose.connection.once('connected', function() {
        console.log("Database connected successfully")
});
// printing to console when we start node server
console.log('todo list hey hey RESTful API server started on: ' + port);
app.use(function(req, res) {
  res.status(404).send({url: req.originalUrl + ' not found'})
});
//console.log('todo list RESTful API server started on: ' + port);
