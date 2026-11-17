const {chromium}=require('playwright');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const {pathToFileURL}=require('node:url');

const root=path.resolve(process.argv[2]);
const output=path.resolve(process.argv[3]);
const run='run-w01-445a3a164ae14723b82f90634cff96f5';

(async()=>{
  fs.mkdirSync(output,{recursive:true});
  const browser=await chromium.launch({headless:true,...(process.env.PLAYWRIGHT_CHANNEL?{channel:process.env.PLAYWRIGHT_CHANNEL}:{})});
  const reports=[];
  try{
    for(const lang of ['en','zh-CN'])for(const mobile of [false,true]){
      const context=await browser.newContext({locale:lang,offline:true,deviceScaleFactor:2,viewport:mobile?{width:390,height:844}:{width:1440,height:1050}});
      const page=await context.newPage(),errors=[],checked=[];
      page.on('pageerror',error=>errors.push(error.message));
      try{
        const url=new URL(pathToFileURL(path.join(root,'workspace',lang,'index.html')).href);
        url.search=new URLSearchParams({run,lang,lens:'file-artifact',detail:'raw',live:'0'}).toString();
        await page.goto(url.href);
        await page.locator('#dag [data-id="workspace_file/result.txt"]').click();
        await page.locator('[data-inspection-tab="content"]').click();
        await page.waitForFunction(()=>document.querySelector('#content-body')?.textContent==='value=2\ncontrolled-write\n');
        const check=async id=>{
          const control=page.locator('#'+id),before=await control.inputValue();
          assert.ok(await control.isVisible(),id+' remains a dropdown');
          await control.click();
          const info=await control.evaluate(el=>{
            const picker=getComputedStyle(el,'::picker(select)');
            const options=[...el.options].filter(o=>!o.hidden).map(o=>({rect:o.getBoundingClientRect().toJSON(),font:getComputedStyle(o).fontSize}));
            return {open:el.matches(':open'),anchor:el.getBoundingClientRect().toJSON(),appearance:picker.appearance,font:getComputedStyle(el).fontSize,pickerFont:picker.fontSize,pickerHeight:parseFloat(picker.height),options,viewport:{width:innerWidth,height:innerHeight}};
          });
          assert.equal(info.open,true,id+' opens on click');
          assert.equal(info.appearance,'base-select',id+' uses the page-rendered picker');
          assert.equal(info.pickerFont,info.font,id+' picker font follows its control');
          assert.ok(info.pickerHeight<=Math.min(360,info.viewport.height*.6)+1,id+' has bounded menu height');
          for(const option of info.options){
            assert.equal(option.font,info.font,id+' option font follows its control');
            assert.ok(option.rect.left>=0&&option.rect.right<=info.viewport.width+1,id+' options stay inside the viewport');
          }
          if(id==='content-choice'){
            const top=info.options[0].rect.top-5,bottom=top+info.pickerHeight;
            assert.ok(Math.min(Math.abs(top-info.anchor.bottom),Math.abs(bottom-info.anchor.top))<=10,'content menu stays anchored to its control');
          }
          await page.screenshot({path:path.join(output,`${lang}-${mobile?'mobile':'desktop'}-${id}.png`)});
          await control.press('Escape');
          assert.equal(await control.evaluate(el=>el.matches(':open')),false,id+' closes on Escape');
          assert.equal(await control.inputValue(),before,id+' cancellation preserves selection');
          assert.equal(await control.evaluate(el=>document.activeElement===el),true,id+' returns focus');
          checked.push(id);
        };
        for(const id of ['runsel','lenssel','detailsel','content-choice'])await check(id);
        const choice=page.locator('#content-choice');
        await choice.click();
        await page.locator('#content-choice option').nth(1).click();
        await page.waitForFunction(()=>document.querySelector('#content-body')?.textContent.includes('agentprov.provenance.object.v1'));
        await choice.press('Space');
        await page.keyboard.press('Home');
        await page.keyboard.press('Enter');
        await page.waitForFunction(()=>document.querySelector('#content-body')?.textContent==='value=2\ncontrolled-write\n');
        await page.locator('#content-expand').click();
        await check('content-choice');
        await page.locator('#content-close').click();
        await page.locator('[data-context-open="conversation"]').first().click();
        await check('context-source');
        await page.locator('#compliance-fold summary').click();
        await check('fwsel');
        await page.locator('[data-investigation="compare"]').click();
        await check('compare-a');
        await check('compare-b');
        await page.locator('#compare-close').click();
        assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1),'page has no horizontal overflow');
        assert.deepEqual(errors,[]);
        reports.push({language:lang,mobile,offline:true,status:'PASS',controls:checked});
      }finally{await context.close();}
    }
  }finally{
    await browser.close();
    fs.writeFileSync(path.join(output,'report.json'),JSON.stringify({reports},null,2)+'\n');
  }
  console.log(JSON.stringify({dropdownsPassed:true,reports}));
})().catch(error=>{console.error(error);process.exitCode=1;});
