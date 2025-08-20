const md5_hash = Module.cwrap("md5_hash", 'string', ['string']) 

$(document).ready(() => {
    $("#hash").click((e)=>{
        var inputText = $("#input").val();
        if (inputText != "") 
        {
            $("#output").val(md5_hash(inputText));
        }
    });
});

