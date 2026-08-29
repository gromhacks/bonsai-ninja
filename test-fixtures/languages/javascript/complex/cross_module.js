// cross_module.js - Cross-module flow chains spanning all 5 example files
//
// Imports from:
//   server.js       - app, connectDB
//   controllers.js  - ProductController, UserController, OrderController
//   services.js     - SearchService, PricingService, InventoryService, EmailService, ImageService
//   models.js       - ProductModel, UserModel, OrderModel
//   middleware.js   - authMiddleware, rateLimiter, corsMiddleware, errorHandler,
//                     requestLogger, sanitizeInput, csrfProtection, validateContentType

const { app, connectDB } = require('./server');
const { ProductController, UserController, OrderController } = require('./controllers');
const { SearchService, PricingService, InventoryService, EmailService, ImageService } = require('./services');
const { ProductModel, UserModel, OrderModel } = require('./models');
const { authMiddleware, rateLimiter, requestLogger, sanitizeInput, corsMiddleware, errorHandler } = require('./middleware');
const EventEmitter = require('events');
const { exec } = require('child_process');


// ---------------------------------------------------------------------------
// Chain A: Deep interprocedural - HTTP request through 4 files to MongoDB
//
// VULN: NoSQL injection (10+ hops across 4 files)
// Flow: cross_module.js:handleDeepSearch (req.body.query)
//    -> cross_module.js:routeSearchRequest
//    -> cross_module.js:delegateToController
//    -> controllers.js:ProductController.search (via searchService.searchProducts)
//    -> services.js:SearchService.searchProducts
//    -> services.js:SearchService._buildQuery
//    -> services.js:SearchService._applyFilters
//    -> services.js:SearchService._applySorting
//    -> services.js:SearchService (collection.find with tainted filter)
//    -> MongoDB execute
// ---------------------------------------------------------------------------

function extractSearchParams(requestBody) {
    const params = requestBody.query;
    return params;
}

function enrichSearchParams(params) {
    const enriched = Object.assign({}, params);
    enriched.timestamp = Date.now();
    return enriched;
}

function routeSearchRequest(enrichedParams, db) {
    const searchService = new SearchService(db);
    const results = searchService.searchProducts(enrichedParams);
    return results;
}

function delegateToController(req, db) {
    const params = extractSearchParams(req.body);
    const enriched = enrichSearchParams(params);
    return routeSearchRequest(enriched, db);
}

async function handleDeepSearch(req, res) {
    // VULN: Chain A - NoSQL injection: req.body.query flows through 4 files
    // cross_module.js -> controllers.js -> services.js -> MongoDB
    const db = await connectDB();
    const results = await delegateToController(req, db);
    res.json({ results });
}

app.post('/api/cross/search', handleDeepSearch);


// ---------------------------------------------------------------------------
// Chain B: Module-level variable - store tainted data, read later
//
// VULN: NoSQL injection via module-level variable (3 files)
// Flow: cross_module.js:captureUserFilter (req.query -> cachedFilter)
//    -> cross_module.js:cachedFilter (module-level variable)
//    -> cross_module.js:executeCachedSearch
//    -> models.js:UserModel.searchUsers (direct MongoDB query)
//    -> MongoDB execute
// ---------------------------------------------------------------------------

let cachedFilter = null;

function captureUserFilter(req) {
    cachedFilter = req.query;
}

async function executeCachedSearch(db) {
    if (!cachedFilter) {
        return [];
    }
    const userModel = new UserModel(db);
    const results = await userModel.searchUsers(cachedFilter);
    return results;
}

app.get('/api/cross/capture-filter', (req, res) => {
    // VULN: Chain B - stores raw user input in module variable
    captureUserFilter(req);
    res.json({ status: 'filter cached' });
});

app.get('/api/cross/run-cached', async (req, res) => {
    // VULN: Chain B - reads tainted module variable, passes to MongoDB
    // cross_module.js:cachedFilter -> models.js:UserModel.searchUsers -> MongoDB
    const db = await connectDB();
    const results = await executeCachedSearch(db);
    res.json({ results });
});


// ---------------------------------------------------------------------------
// Chain C: Callback/event chain - EventEmitter bridges files
//
// VULN: Command injection via event callback (4 files)
// Flow: cross_module.js:handleImageUpload (req.body.filename)
//    -> cross_module.js:imageEventBus.emit('process', filename)
//    -> cross_module.js:event listener callback
//    -> cross_module.js:processImageWithLogging(filename)
//    -> services.js:ImageService.processImage(filename)
//    -> child_process.exec with tainted filename
// ---------------------------------------------------------------------------

const imageEventBus = new EventEmitter();

function processImageWithLogging(filename, options, imageService) {
    requestLogger;  // reference to middleware (imported for logging context)
    return imageService.processImage(filename, options);
}

imageEventBus.on('process', function onImageProcess(data) {
    const imageService = new ImageService();
    processImageWithLogging(data.filename, data.options, imageService);
});

async function handleImageUpload(req, res) {
    // VULN: Chain C - command injection via event-driven callback
    // cross_module.js -> EventEmitter -> services.js:ImageService.processImage -> exec
    const filename = req.body.filename;
    const options = { size: req.body.size || '800x600' };
    imageEventBus.emit('process', { filename, options });
    res.json({ status: 'processing' });
}

app.post('/api/cross/upload', handleImageUpload);


// ---------------------------------------------------------------------------
// Chain D: Re-exported wrapper - wraps imported function, called with taint
//
// VULN: Command injection via wrapped service function (3 files)
// Flow: cross_module.js:handleInventoryExport (req.query.format)
//    -> cross_module.js:formatAndValidate(format)
//    -> cross_module.js:exportWithAudit(format)
//    -> cross_module.js:wrappedExportInventory(format, outputPath)
//    -> services.js:InventoryService.exportInventory(format, outputPath)
//    -> child_process.exec with tainted format
// ---------------------------------------------------------------------------

let inventoryServiceInstance = null;

async function initInventoryService() {
    const db = await connectDB();
    inventoryServiceInstance = new InventoryService(db);
}

function wrappedExportInventory(format, outputPath) {
    return inventoryServiceInstance.exportInventory(format, outputPath);
}

function formatAndValidate(rawFormat) {
    const format = rawFormat.trim();
    return format;
}

async function exportWithAudit(format, outputPath) {
    const result = await wrappedExportInventory(format, outputPath);
    return result;
}

async function handleInventoryExport(req, res) {
    // VULN: Chain D - command injection through re-exported wrapper
    // cross_module.js:formatAndValidate -> wrappedExportInventory
    //   -> services.js:InventoryService.exportInventory -> exec
    await initInventoryService();
    const format = formatAndValidate(req.query.format);
    const outputPath = '/tmp/inventory_report';
    const result = await exportWithAudit(format, outputPath);
    res.json({ result });
}

app.get('/api/cross/export-inventory', handleInventoryExport);


// ---------------------------------------------------------------------------
// Chain E: Recursive processing - user input in recursive tree traversal
//
// VULN: Command injection via recursive category expansion (3 files)
// Flow: cross_module.js:handleCategoryReport (req.body.category)
//    -> cross_module.js:expandCategory(category, depth)
//    -> cross_module.js:expandCategory (recursive call N times)
//    -> cross_module.js:buildReportCommand(expandedCategory)
//    -> child_process.exec with tainted category name
// ---------------------------------------------------------------------------

function expandCategory(category, depth) {
    if (depth <= 0) {
        return category;
    }
    const subCategory = category + '/sub';
    return expandCategory(subCategory, depth - 1);
}

function buildReportCommand(categoryPath) {
    const cmd = 'generate-category-report --category ' + categoryPath + ' --output /tmp/cat_report';
    return cmd;
}

function executeReport(cmd) {
    return new Promise((resolve, reject) => {
        exec(cmd, (err, stdout) => {
            if (err) reject(err);
            else resolve(stdout);
        });
    });
}

async function handleCategoryReport(req, res) {
    // VULN: Chain E - command injection via recursive category expansion
    // cross_module.js:handleCategoryReport -> expandCategory (recursive)
    //   -> buildReportCommand -> exec
    const category = req.body.category;
    const expandedCategory = expandCategory(category, 3);
    const cmd = buildReportCommand(expandedCategory);
    const output = await executeReport(cmd);
    res.json({ output });
}

app.post('/api/cross/category-report', handleCategoryReport);


// ---------------------------------------------------------------------------
// Safe variant: sanitized input does NOT flow to sinks
// ---------------------------------------------------------------------------

async function handleSafeSearch(req, res) {
    const rawInput = req.query.q;
    const safeInput = sanitizeInput(rawInput);
    // Safe: sanitizeInput from middleware.js escapes dangerous characters
    res.send('<p>Results for: ' + safeInput + '</p>');
}

app.get('/api/cross/safe-search', handleSafeSearch);


// ---------------------------------------------------------------------------
// Wire up middleware from middleware.js on cross-module routes
// ---------------------------------------------------------------------------

app.use('/api/cross/export-inventory', authMiddleware);
app.use('/api/cross/category-report', authMiddleware);
app.use('/api/cross', rateLimiter(60000, 100));
app.use(corsMiddleware);
app.use(errorHandler);


module.exports = {
    handleDeepSearch,
    handleImageUpload,
    handleInventoryExport,
    handleCategoryReport,
    handleSafeSearch,
    captureUserFilter,
    executeCachedSearch,
    expandCategory,
    wrappedExportInventory,
    imageEventBus,
};
