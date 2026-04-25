// PhishWall Local ML Engine
// Offline Phishing Detection using TensorFlow.js

self.mlEngineReady = false;
let model;

async function initMLEngine() {
    try {
        await tf.setBackend('cpu');
        await tf.ready();
        
        try {
            model = await tf.loadLayersModel('indexeddb://phishwall-model');
            console.log('PhishWall: Loaded ML model from cache.');
        } catch (e) {
            console.log('PhishWall: Training new offline model...');
            model = await buildAndTrainModel();
            await model.save('indexeddb://phishwall-model');
            console.log('PhishWall: Saved ML model to cache.');
        }
        self.mlEngineReady = true;
    } catch (e) {
        console.error('PhishWall ML Engine initialization failed:', e);
    }
}

async function buildAndTrainModel() {
    const newModel = tf.sequential();
    // Input shape increased to 9 features
    newModel.add(tf.layers.dense({ units: 16, activation: 'relu', inputShape: [9] }));
    newModel.add(tf.layers.dense({ units: 8, activation: 'relu' }));
    newModel.add(tf.layers.dense({ units: 1, activation: 'sigmoid' }));
    
    newModel.compile({ optimizer: 'adam', loss: 'binaryCrossentropy', metrics: ['accuracy'] });
    
    // Feature order: [length, dots, hyphens, subdomains, atSymbol, isHttps, keywordCount, hasNumbers, pathRatio]
    const xs = tf.tensor2d([
        [15,  1, 0, 0, 0, 1, 0, 0, 0.1], // Safe (short)
        [25,  2, 0, 1, 0, 1, 0, 0, 0.2], // Safe (normal)
        [60,  2, 1, 0, 0, 1, 0, 0, 0.4], // Safe (long article)
        [90,  3, 2, 0, 0, 1, 0, 0, 0.7], // Safe (very long valid URL)
        [85,  4, 2, 3, 0, 0, 2, 1, 0.6], // Phishing
        [120, 5, 3, 4, 1, 0, 3, 1, 0.8], // Phishing
        [20,  1, 0, 0, 0, 1, 0, 0, 0.1], // Safe
        [90,  3, 1, 2, 0, 0, 1, 1, 0.5]  // Phishing
    ]);
    const ys = tf.tensor2d([[0], [0], [0], [0], [1], [1], [0], [1]]);
    
    await newModel.fit(xs, ys, { epochs: 50, verbose: 0 });
    
    xs.dispose();
    ys.dispose();
    return newModel;
}

function extractFeatures(urlStr) {
    try {
        const url = new URL(urlStr);
        const length = urlStr.length;
        const dots = (url.hostname.match(/\./g) || []).length;
        const hyphens = (url.hostname.match(/-/g) || []).length;
        const subdomains = dots > 1 ? dots - 1 : 0;
        const atSymbol = urlStr.includes('@') ? 1 : 0;
        const isHttps = url.protocol === 'https:' ? 1 : 0;
        
        // New Features
        const keywords = ['login', 'secure', 'update', 'account', 'verify', 'bank', 'signin', 'password', 'auth'];
        let keywordCount = 0;
        const urlLower = urlStr.toLowerCase();
        for (const kw of keywords) {
            if (urlLower.includes(kw)) keywordCount++;
        }
        
        const hasNumbers = /\d/.test(url.hostname) ? 1 : 0;
        const pathRatio = url.pathname.length / length;
        
        return [length, dots, hyphens, subdomains, atSymbol, isHttps, keywordCount, hasNumbers, pathRatio];
    } catch (e) {
        return [0, 0, 0, 0, 0, 0, 0, 0, 0];
    }
}

async function predictUrl(urlStr) {
    if (!self.mlEngineReady || !model) {
        return null;
    }
    
    const features = extractFeatures(urlStr);
    const tensor = tf.tensor2d([features]);
    
    const prediction = model.predict(tensor);
    const score = prediction.dataSync()[0];
    
    tensor.dispose();
    prediction.dispose();
    
    return score;
// Initialize engine
initMLEngine();

