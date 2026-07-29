/**
 * Test: Express.js — file download, findById without auth, admin route.
 *
 * Meta-inspired: unprotected file attachments in support tickets.
 */

const express = require('express');
const app = express();

// VULN: File download from req.params without auth
app.get('/files/:fileId', (req, res) => {
    res.sendFile(`/uploads/${req.params.fileId}`);  // GS007: Express sendFile
});

// VULN: findById without auth middleware
app.get('/api/tickets/:id', (req, res) => {
    Ticket.findById(req.params.id).then(ticket => {  // GS007: Express findById
        res.json(ticket);
    });
});

// VULN: Admin route without auth
app.get('/admin/users', (req, res) => {  // GS007: admin route
    User.find({}).then(users => res.json(users));
});

// OK: Has auth middleware (requireAuth)
app.get('/api/secure/:id', requireAuth, (req, res) => {
    Ticket.findByPk(req.params.id).then(ticket => res.json(ticket));
});
