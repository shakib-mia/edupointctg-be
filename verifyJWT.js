const jwt = require("jsonwebtoken");

const verifyJWT = (req, res, next) => {
  const currentTime = new Date().getTime();
  const { token } = req.headers;
  // console.log(token);
  if (!token) {
    return res.status(401).send("Unauthorized: Token missing");
  }

  try {
    const user = jwt.verify(token, process.env.access_token_secret, {
      algorithms: "RS256",
    });
    console.log(token);

    if (currentTime >= user.exp * 1000) {
      return res.status(401).send({ message: "Token has expired" });
    }

    next();
  } catch (err) {
    res.status(401).send(err);
    // console.log(err.name, err.message, err);
  }
};

module.exports = verifyJWT;
