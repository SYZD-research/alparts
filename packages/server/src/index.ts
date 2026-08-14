import { createApp } from './app.js';
import { config } from './config/index.js';

const { httpServer } = createApp();

httpServer.listen(config.port, () => {
  console.log(`Server running on port ${config.port}`);
  console.log(`Environment: ${config.nodeEnv}`);
});
