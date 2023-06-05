const express = require("express");
const cors = require("cors");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");

require("dotenv").config();
const session = require("express-session");
const app = express();
app.use(express.json());
// connect to db
mongoose
  .connect(process.env.DATABASE, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("DB connected"))
  .catch((err) => console.log("DB CONNECTION ERROR: ", err));

// app middlewares
//app.use(bodyParser.json());



//app.use(bodyParser.urlencoded({ limit: "50mb", extended: true }));
app.use(cors()); // allows all origins

//express seession
app.use(
  session({
    secret: process.env.SESSION_SECRET, // Replace with your own secret key
    resave: false,
    saveUninitialized: true,
    cookie: {
      secure: false, // Set it to true if using HTTPS
      maxAge: 3600000, // Session expiration time in milliseconds (e.g., 1 hour)
    },
  })
);

// routes attached with server
app.use("/api", require("./routes/auth"));
app.use("/api", require("./routes/adminSupportUser"));

//app.use("/api", require("./routes/auth"));

const port = process.env.PORT || 5001;
const swaggerUi = require("swagger-ui-express");

const swaggerDocument = require("./swagger.json");

app.use("/api-docs", swaggerUi.serve, swaggerUi.setup(swaggerDocument));

app.listen(port, () => {
  console.log(`API is running on port ${port}`);
});

app.get("/", (req, res) => {
  res.send("Hello World!");
});
