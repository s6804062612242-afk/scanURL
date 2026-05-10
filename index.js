const express = require('express');
const path = require('path');
const app = express();

app.use(express.static(path.join(__dirname, 'frontend')));


//route 
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname,'index.html'));
});



//api


//test

app.listen(3000, () => {
    console.log('Server is running on port 3000');
});
