const test=require('node:test');
const assert=require('node:assert/strict');
const crypto=require('node:crypto');
const createOrder=require('../api/create-order.js');
const verifyPayment=require('../api/verify-payment.js');

function response(){
  return {
    code:200, body:null, headers:{},
    setHeader(name,value){this.headers[name]=value;return this;},
    status(code){this.code=code;return this;},
    json(body){this.body=body;return this;}
  };
}
function config(values,fn){
  const keys=['RAZORPAY_KEY_ID','RAZORPAY_KEY_SECRET','REGISTRATION_FEE_INR'];
  const previous=Object.fromEntries(keys.map(key=>[key,process.env[key]]));
  for(const key of keys){if(Object.hasOwn(values,key))process.env[key]=values[key];else delete process.env[key];}
  return Promise.resolve().then(fn).finally(()=>{
    for(const key of keys){if(previous[key]===undefined)delete process.env[key];else process.env[key]=previous[key];}
  });
}

test('order creation requires private server-side payment credentials',()=>config({},async()=>{
  const res=response();
  await createOrder({method:'POST',body:{name:'Sample',committee:'MCC'}},res);
  assert.equal(res.code,503);
}));
test('order creation rejects malformed JSON before contacting gateway',()=>config({RAZORPAY_KEY_ID:'id',RAZORPAY_KEY_SECRET:'secret',REGISTRATION_FEE_INR:'100'},async()=>{
  const res=response();
  await createOrder({method:'POST',body:'{invalid json'},res);
  assert.equal(res.code,400);
}));
test('order creation rejects unknown committee and invalid guest details',()=>config({RAZORPAY_KEY_ID:'id',RAZORPAY_KEY_SECRET:'secret',REGISTRATION_FEE_INR:'100'},async()=>{
  const res=response();
  await createOrder({method:'POST',body:{name:'Sample',committee:'UNKNOWN'}},res);
  assert.equal(res.code,400);
}));
test('signature verification rejects malformed payloads',()=>config({RAZORPAY_KEY_SECRET:'secret'},async()=>{
  const res=response();
  await verifyPayment({method:'POST',body:'{invalid json'},res);
  assert.equal(res.code,400);
}));
test('signature verification requires an HMAC computed with server secret',()=>config({RAZORPAY_KEY_SECRET:'test-secret'},async()=>{
  const order='order_123',payment='pay_123';
  const signature=crypto.createHmac('sha256','test-secret').update(order+'|'+payment).digest('hex');
  const success=response();
  await verifyPayment({method:'POST',body:{razorpay_order_id:order,razorpay_payment_id:payment,razorpay_signature:signature}},success);
  assert.equal(success.body.verified,true);
  const invalid=response();
  await verifyPayment({method:'POST',body:{razorpay_order_id:order,razorpay_payment_id:payment,razorpay_signature:'0'.repeat(64)}},invalid);
  assert.equal(invalid.code,400);
}));
