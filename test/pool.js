var Fiber = require('fibers');
const { AsyncLocalStorage } = require('async_hooks');

for (var jj = 0; jj < 10; ++jj) {
	var fibers = [];
	for (var ii = 0; ii < 200; ++ii) {
		var fn = Fiber(function() {
			Fiber.yield();
		});
		fn.run();
		fibers.push(fn);
	}
	for (var ii = 0; ii < fibers.length; ++ii) {
		fibers[ii].run();
	}
}

var result = 'pass';
var _storage = new AsyncLocalStorage();
if (typeof _storage.getStore() !== 'undefined') {
	result = 'fail';
	throw new Error('storage should be undefined outside of .run call');
}
_storage.run(123, function() {
	if (_storage.getStore() !== 123) {
		result = 'fail';
		throw new Error('store should persist values');
	}
});

_storage.run(456, function() {
	if (_storage.getStore() !== 456) {
		result = 'fail';
		throw new Error('store should persist new values');
	}
})

_storage.run({}, function() {
	_storage.getStore()['doodad'] = 456;
	if (_storage.getStore()['doodad'] !== 456) {
		result = 'fail';
		throw new Error('mutable stores should reflect changes');
	}
})

_storage.run(789, function() {
	_storage.disable();
	if (typeof _storage.getStore() !== 'undefined') {
		result = 'fail';
		throw new Error('.disable should make .getStore calls in .run return undefined');
	}
})

console.log(result);
