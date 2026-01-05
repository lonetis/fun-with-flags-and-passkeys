import app from './app';
import { startCleanupScheduler } from './services/cleanup';

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`
  ╔═══════════════════════════════════════════════════════════╗
  ║                                                           ║
  ║   🚩 Fun with Flags - Passkey Security Learning Platform  ║
  ║                                                           ║
  ║   Server running at http://localhost:${PORT}                 ║
  ║                                                           ║
  ╚═══════════════════════════════════════════════════════════╝
  `);

  startCleanupScheduler();
});
