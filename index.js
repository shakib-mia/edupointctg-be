const express = require("express");
const cors = require("cors");
const port = process.env.PORT || 5000;
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

require("dotenv").config();

const app = express();

app.use(express.json());
app.use(cors());

app.get("/", (req, res) => {
  res.send(`from port ${port}`);
});

const { MongoClient, ServerApiVersion } = require("mongodb");
const uri = `mongodb+srv://smdshakibmia2001:${process.env.password}@cluster0.v1wxtqe.mongodb.net/?retryWrites=true&w=majority`;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
    useUnifiedTopology: true,
  },
});
const saltRounds = 10;

async function run() {
  try {
    await client.connect();
    const usersCollection = client.db("edupointctg").collection("users");

    app.post("/register", async (req, res) => {
      // const {body} =
      const { email } = req.body;
      const exist = await usersCollection.findOne({ email });
      // console.log(!exist);
      if (!exist) {
        // console.log(req.body);
        const { body } = req;
        bcrypt.hash(body.password, saltRounds, async (err, hash) => {
          body.password = hash;
          // console.log(body);

          const cursor = await usersCollection.insertOne(body);
          // res.send(cursor);
          if (cursor.insertedId) {
            const token = jwt.sign(
              { _id: cursor.insertedId },
              process.env.access_token_secret,
              {
                expiresIn: "1h",
              }
            );

            res.send({ token });
          }
        });
      } else {
        res.status(409).json({ error: "User already exists with this email." });
      }
    });

    app.post("/login", (req, res) => {});
  } finally {
  }
}
run().catch(console.dir);

app.listen(port, () => console.log(`listening on port`, port));
