/* Client flow checks with a DOM test double; this does not render a browser. */
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const source = fs.readFileSync(path.join(__dirname, "../samples/demo_web/storefront.js"), "utf8");
let checks = 0;
function check(condition, message) { assert(condition, message); checks++; }

async function runTheme(platform, theme) {
  const nodes = new Map();
  function element(id) {
    if (nodes.has(id)) return nodes.get(id);
    let html = "";
    const classes = new Set();
    const node = {id, value:"", textContent:"", checked:false, disabled:false, hidden:false, open:false, dataset:{}, listeners:{},
      classList:{add(...items){items.forEach((item)=>classes.add(item));}, remove(item){classes.delete(item);}, toggle(item, state){if(state)classes.add(item);else classes.delete(item);}, contains(item){return classes.has(item);}},
      addEventListener(name, callback){this.listeners[name] = callback;}, querySelectorAll(){return [];},
      showModal(){this.open=true;}, close(){this.open=false;}, scrollIntoView(){},
    };
    Object.defineProperty(node,"innerHTML",{get(){return html;},set(value){html=value;if(["targetRoute","targetOrder"].includes(id)){
      const options=[...String(value).matchAll(/<option value="([^"]*)"/g)].map((m)=>m[1]);
      if(!options.includes(node.value))node.value=options[0]||"";
    }}});
    nodes.set(id,node);return node;
  }
  const config={platform,theme,name:"TEST STORE",title:"테스트 스토어",eyebrow:"COLLECTION",description:"시연 상품",badge:"DEMO",collection:"상품"};
  element("demo-config").textContent=JSON.stringify(config);
  element("buyerName").value='<img src=x onerror=alert(1)>';
  element("buyerEmail").value="demo@example.test";
  element("buyerAddress").value="가상 수령지";
  element("newTestOrder").checked=true;
  element("teamFeed").hidden=true;
  const scenarios=["normal","expired","invalid_signature","missing_signature"].map((scenario)=>({dataset:{scenario},disabled:false,listeners:{},addEventListener(name,cb){this.listeners[name]=cb;}}));
  const state={products:[{id:"P1",name:"데모 상품",price:24000,stock:20,kind:"mug",tone:"#79917f",category:"리빙",tag:"NEW"}],orders:[],logs:[],paths:["/webhook/test","/webhook/test-fixed"],stats:{total:0,processed:0,pending:0}};
  const requests=[];
  let sequence=0;
  const clone=(value)=>JSON.parse(JSON.stringify(value));
  function record(order,scenario,path) {
    const rejected=scenario.includes("signature")||(scenario==="expired"&&path.endsWith("-fixed"));
    const before=order.status;
    if(!rejected)order.status=platform==="slack"?"processed":"paid";
    const log={id:"log"+(++sequence),order_id:order.order_id,scenario,path,http_status:rejected?401:200,before,after:order.status,state_changed:before!==order.status,
      at:new Date().toISOString(),request_headers:{"X-Test":"signed"},request_body:{event:{text:"실제 시험 알림"}},response:{accepted:!rejected}};
    state.logs.unshift(log);return log;
  }
  async function fetchMock(url, options={}) {
    const data=options.body?JSON.parse(options.body):undefined;
    requests.push({url,data});
    let result;
    if(url==="/demo/state") {
      state.stats={total:state.orders.length,processed:state.orders.filter((o)=>o.status!=="pending").length,pending:state.orders.filter((o)=>o.status==="pending").length};
      result=state;
    } else if(url==="/demo/order") {
      const order={order_id:"order"+(++sequence),status:"pending",payment_status:"pending",provider_status:"not_requested",source:"storefront",items:[{...state.products[0],quantity:data.items[0].quantity}],
        product_name:"데모 상품",amount:24000*data.items[0].quantity,customer:data.customer,delivery:data.delivery,created_at:new Date().toISOString()};
      state.orders.unshift(order);result=order;
    } else if(url==="/demo/pay") {
      const order=state.orders.find((row)=>row.order_id===data.order_id);
      order.provider_status="approved";order.payment_status="paid";
      result={order,delivery:record(order,"normal",state.paths[0])};
    } else if(url==="/demo/send") {
      const order={order_id:"trial"+(++sequence),status:"pending",source:"security_demo",payment_status:"pending",product_name:"시험 상품",amount:24000};
      state.orders.unshift(order);result={order,delivery:record(order,data.scenario,data.path)};
    } else if(url==="/demo/reset") {state.orders=[];state.logs=[];result={ok:true};}
    else throw new Error("Unexpected client URL: "+url);
    return {ok:true,json:async()=>clone(result)};
  }
  const document={body:element("body"),title:"",hidden:false,getElementById:element,
    querySelector(selector){return {value:selector.includes("delivery")?"pickup":"demo_card"};},
    querySelectorAll(selector){return selector.includes("data-scenario")?scenarios:[];}};
  const context={document,window:{confirm:()=>true},fetch:fetchMock,console,Map,Set,Date,JSON,Number,String,Error,
    setTimeout:()=>1,clearTimeout(){},setInterval:()=>1};
  vm.createContext(context);vm.runInContext(source,context);
  await new Promise(setImmediate);
  check(document.body.classList.contains("theme-"+theme),platform+": theme selected");
  check(element("productGrid").innerHTML.includes("데모 상품"),platform+": products rendered");
  check(!element("teamFeed").hidden === (platform==="slack"),platform+": Slack panel visibility");
  const click={target:{closest:(selector)=>selector==="[data-add]"?{dataset:{add:"P1"}}:null}};
  element("productGrid").listeners.click(click);element("productGrid").listeners.click(click);
  check(element("cartCount").textContent===2,platform+": cart count");
  element("openCart").listeners.click();check(element("checkoutDialog").open,platform+": checkout dialog");
  await element("checkoutForm").listeners.submit({preventDefault(){}});
  const orderRequest=requests.find((row)=>row.url==="/demo/order");
  check(orderRequest.data.items[0].quantity===2,platform+": quantity sent");
  check(!("amount" in orderRequest.data)&&!("price" in orderRequest.data.items[0]),platform+": no trusted client price");
  check(element("paymentDialog").open&&!element("checkoutDialog").open,platform+": payment step follows order");
  check(!element("orderList").innerHTML.includes('<img src=x'),platform+": customer HTML escaped");
  await element("paymentForm").listeners.submit({preventDefault(){}});
  check(!element("paymentDialog").open,platform+": payment completed");
  check(element("evidence").innerHTML.includes("HTTP 200"),platform+": real-response evidence rendered");
  check(requests.some((row)=>row.url==="/demo/pay"&&row.data.method==="demo_card"),platform+": payment action sent");
  element("targetRoute").value="/webhook/test-fixed";
  await scenarios[1].listeners.click();
  const sendRequest=requests.findLast((row)=>row.url==="/demo/send");
  check(sendRequest.data.new_order&&sendRequest.data.scenario==="expired"&&sendRequest.data.path.endsWith("-fixed"),platform+": isolated trial and selected fixed path");
  check(element("evidence").innerHTML.includes("HTTP 401"),platform+": rejection shown");
  check(element("targetRoute").value==="/webhook/test-fixed",platform+": route retained after refresh");
  check(element("requestPreview").textContent.includes('"HTTP응답": 401'),platform+": request response details");
  check(vm.runInContext('escapeHTML("<script>unsafe</script>")',context)==="&lt;script&gt;unsafe&lt;/script&gt;",platform+": escaping");
  await element("resetDemo").listeners.click();
  check(state.orders.length===0&&element("orderList").innerHTML.includes("아직 주문한 상품"),platform+": reset flow");
}

(async()=>{
  for(const [platform,theme] of [["toss","campus"],["stripe","studio"],["slack","team"],["generic","neighborhood"]])await runTheme(platform,theme);
  process.stdout.write(`Storefront DOM test-double checks: ${checks} passed. Browser layout not rendered.\n`);
})().catch((error)=>{console.error(error);process.exitCode=1;});
