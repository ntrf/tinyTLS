var async = require('async'), 
fs = require('fs'), 
http = require('http'), 
util = require('util');

var additional = process.argv.slice(2);

var stream = require('stream');

var splitting_re = /\r\n|\r|\n/;
var empty_re = /^\s*(?:\#|$)/;
var ReadlineStream = function (options) 
{
	if (!(this instanceof ReadlineStream))
		return new ReadlineStream(options);

	stream.Transform.call(this, options)

	// use objectMode to stop the output from being buffered
	// which re-concatanates the lines, just without newlines.
	this._readableState.objectMode = true;

	var lineBuffer = '';

	// take the source's encoding if we don't have one
	this.on('pipe', function(src) {
		if (!this.encoding) {
			this.encoding = src._readableState.encoding;
		}
	});

	this._transform = function(chunk, encoding, done) 
	{
		// decode binary chunks as UTF-8
		if (Buffer.isBuffer(chunk)) {
			if (!encoding || encoding == 'buffer') encoding = 'utf8';

			chunk = chunk.toString(encoding);
		}

		lineBuffer += chunk;
		var lines = lineBuffer.split(splitting_re);

		var last = lines.pop();

		lines = lines.filter(function(v) {
			return (!v.match(empty_re))
		});

		lines.forEach(this.push.bind(this));
		lineBuffer = last;

		done();
	};

	this._flush = function(done) 
	{
		if(lineBuffer) {
			this.push(lineBuffer);
			lineBuffer = '';
		}

		done();
	};
};
util.inherits(ReadlineStream, stream.Transform);

var source_url = "http://mxr.mozilla.org/mozilla-central/source/security/nss/lib/ckfw/builtins/certdata.txt?raw=1"

var ck_attrib = /^\s*CKA_([\w_]+)\s*([\w_]+)\s*([\w_]+)/i;
var ck_attrib_ml = /^\s*CKA_([\w_]+)\s*MULTILINE_([\w_]+)/i;

var multiline_vals = /\\\d+/g;

function MergeObjects(input) {
	// parse file into objects
	var lc = input.length;
	var i = 0;
	
	var certs = [];
	var trusts = [];
	
	var currentobj = null;
	
	for (; i < lc; ++i) {
		var attr = {};
		
		var f = input[i].match(ck_attrib_ml);
		
		if (f) {
			// parse multiline
			++i;
			var full_value = [];
			
			for(; i < lc; ++i) {
				if (/END/.test(input[i])) {
					break;
				}
				
				var vals = input[i].match(multiline_vals);
				full_value = full_value.concat(vals.map(function(v){ return parseInt(v.slice(1), 8); }));
			}
			
			attr.name = f[1];
			attr.value = new Buffer(full_value);
		} else {
			var f = input[i].match(ck_attrib);
			if (!f) continue;
		
			attr.name = f[1];
			attr.value = (f[2] == 'CK_BBOOL') ? (f[3] == 'CK_TRUE') : f[3];
		}
		
		if (attr.name == 'CLASS') {
			if (attr.value == 'CKO_CERTIFICATE') {
				currentobj = {};
				certs.push(currentobj);
			} else if (attr.value == 'CKO_NSS_TRUST') {
				currentobj = {};
				trusts.push(currentobj);
			} else {
				currentobj = null;
			}
			continue;
		}
		
		if (!currentobj) { continue; }
		
		currentobj[attr.name] = attr.value;
	}
	
	return { cr:certs, tr: trusts };
};

function skipSequenceTag(pos, buf)
{
	if (buf[pos] != 0x30) return {pos: 0};
	++pos;
	var len = buf[pos];
	if (len < 0x80) {
		return {pos: (pos+1), len: len};
	} else {
		len -= 0x80;
		pos += len + 1;
		return {pos: pos};
	}
}
function skipTag(pos, buf)
{
	++pos;
	var len = buf[pos];
	if (len < 0x80) {
		return {pos: (pos+1), len: len};
	} else {
		len -= 0x80;
		pos += len + 1;
		return {pos: pos};
	}
}
function skipContent(pos, buf)
{
	++pos;
	var len = buf[pos];
	if (len < 0x80) {
		pos += 1 + len;
		return {pos: pos};
	} else {
		len -= 0x80;
		pos += len + 1;
		return {pos: pos};
	}
}


function findIssuer(buf)
{
	var root = skipTag(0, buf);
	var tbsCert = skipTag(root.pos, buf);
	var serial;
	if (buf[tbsCert.pos] == 0xA0) {
		serial = skipContent(tbsCert.pos, buf);
	} else {
		serial = tbsCert;
	}
	
	var algType = skipContent(serial.pos, buf);
	var issuer = skipContent(algType.pos, buf);
	
	return skipTag(issuer.pos, buf);
}

function GenTrustList(input)
{
	var trusts = input.tr;
	var certs = input.cr;
	
	var bufEq = function(buf1, buf2) {
		if (!Buffer.isBuffer(buf1) || !Buffer.isBuffer(buf2) || (buf1.length != buf2.length))
			return false;
		
		for (var i = 0, m = buf1.length; i < m; ++i) {
			if (buf1[i] != buf2[i]) return false;
		}
		return true;
	};
	
	var findCert = function(issuer) {
		
		for (var i = 0, m = certs.length; i < m; ++i) {
		
			if (bufEq(issuer, certs[i].SUBJECT))
				return i;
		}
		return -1;
	};
	
	var db = [];
	
	for (var i = 0, m = trusts.length; i < m; ++i) {
		var tr = trusts[i];
		
		var cri = findCert(tr.ISSUER);
		if (cri < 0) {
			db.push({
				issuer: tr.ISSUER,
				cert: new Buffer(0)
			});
		} else {
			db.push({
				issuer: tr.ISSUER, 
				cert: certs[cri].VALUE || new Buffer(0)
			});
		}
	}
	
	return db;
};

var cdbwr = require('./writable-cdb.js');

async.waterfall([
	function(cb) {
		http.get(source_url, function(res) {
			res.setEncoding('utf8');
			
			var lines = new ReadlineStream();
			res.pipe(lines);
			
			var output = [];
			
			lines.on('data', function(data) {
				output.push(data);
			});
			lines.on('end', function(){
				cb(null, output);
			});
		}).on('error', function(e) {
			cb("Failed to donwload file: " + e.message, null);
		});
	},
	function(input, cb) {
		var crtr = MergeObjects(input);
		var db = GenTrustList(crtr);
		
		additional.forEach(function(ef) {
			try {
				console.log("adding file: " + ef);
				var data = fs.readFileSync(ef);
				var issuer_pos = findIssuer(data);
				var issuer = data.slice(issuer_pos.pos, issuer_pos.pos + issuer_pos.len);
				
				db.push({
					issuer: issuer,
					cert: data
				});
			} catch (e) {
				console.log("adding file failed: " + e);
			}
		});
		
		cb(null, db);
	},
	function(db, cb) {
		var wr = new cdbwr('./calist.db');
		
		wr.open(function(err) {
			db.forEach(function(v) {
				var sl = skipSequenceTag(0, v.issuer);
				if (sl) {
					wr.put(v.issuer.slice(sl.pos), v.cert);
				}
			});
			
			wr.close(cb);
		});
	}
], function(err) {
	if (err) {
		console.log("[ERROR] " + err);
		return;
	}
});