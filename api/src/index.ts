import express from "express";
import { runAnalysis } from "./engine.js";

const PORT = Number(process.env.PORT) || 3000;

const app = express();

// Middleware
app.use(express.json({ limit: "512kb" }));

app.post("/v1/check", (req, res) => {
  const { text, url } = req.body;

  // Basic validation: must have at least one field
  if (!text && !url) {
    res.status(400).json({ 
      error: "Request must include at least one field: 'text' or 'url'." 
    });
    return;
  }

  // Type validation if present
  if (text && typeof text !== "string") {
    res.status(400).json({ error: "Field 'text' must be a string." });
    return;
  }
  if (url && typeof url !== "string") {
    res.status(400).json({ error: "Field 'url' must be a string." });
    return;
  }

  const result = runAnalysis({ text, url });
  
  res.json(result);
});

app.listen(PORT, () => {
  console.log(`Beacon Multi-Scanner API listening on port ${PORT}`);
});
