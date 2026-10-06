const { Router } = require('express');
const users = require('../controllers/userController');

const router = Router();
router.get('/search', users.search);
router.get('/by-id/:id', users.byId);
router.get('/sorted', users.sorted);

module.exports = router;
