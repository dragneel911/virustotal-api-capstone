import dotenv from "dotenv";
import express from "express";
import bodyParser from "body-parser";
import axios from "axios";

dotenv.config();

const app = express();
const port = 3000;
const apiKey = process.env.API_KEY;

app.set("view engine", "ejs");
app.use(express.static("public"));
app.use(bodyParser.urlencoded({ extended: true }));

app.get("/", (req, res) => {
  res.render("index");
});
app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});

app.post("/scan", async (req, res) => {
  const userUrl = req.body.url;

  try {
    // Step 1: Submit URL to VirusTotal
    const postResponse = await axios.post(
      "https://www.virustotal.com/api/v3/urls",
      new URLSearchParams({ url: userUrl }).toString(),
      {
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          "x-apikey": apiKey,
        },
      }
    );

    // Step 2: Extract the URL ID from response
    const urlId = postResponse.data.data.id;

    // Step 3: Get scan report using the URL ID
    const getResponse = await axios.get(
      `https://www.virustotal.com/api/v3/urls/${urlId}`,
      {
        headers: {
          "x-apikey": apiKey,
        },
      }
    );

    // Step 4: Render the result page and send data
    res.render("result", { result: getResponse.data });

  } catch (error) {
    // Step 5: Error Handling
    if (error.response && error.response.status === 403) {
      res.send("🚫 VirusTotal API rate limit reached. Please try again later.");
    } else {
      console.error("Error:", error.message);
      res.send("Something went wrong. Please try again.");
    }
  }
});




