var page = require('webpage').create();
system = require('system');
var address;
var dstpath;
if(system.args.length == 1){
    phantom.exit();
}else{
    adress = system.args[1];
    dstpath = system.args[2];
    page.open(adress, function (status){
        if (status != "success"){
            console.log('FAIL to load the address');
            phantom.exit();
        }

        //在本地生成截图
        page.render(dstpath);
        phantom.exit();
    });
}
