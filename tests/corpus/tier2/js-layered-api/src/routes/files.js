const express = require('express');
const fileController = require('../controllers/fileController');

const router = express.Router();
router.get('/download', fileController.download);
router.get('/preview', fileController.preview);

module.exports = router;
