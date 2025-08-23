const hash_functions = {
    "md5": Module.cwrap("md5_hash", 'string', ['string']),
    "md4": Module.cwrap("md4_hash", 'string', ['string']),
    "md2": Module.cwrap("md2_hash", 'string', ['string']),
    "blake2s_128": Module.cwrap("blake2s_128_hash", 'string', ['string']),
    "blake2s_160": Module.cwrap("blake2s_160_hash", 'string', ['string']),
    "blake2s_224": Module.cwrap("blake2s_224_hash", 'string', ['string']),
    "blake2s_256": Module.cwrap("blake2s_256_hash", 'string', ['string']),
    "blake2b_160": Module.cwrap("blake2b_160_hash", 'string', ['string']),
    "blake2b_256": Module.cwrap("blake2b_256_hash", 'string', ['string']),
    "blake2b_384": Module.cwrap("blake2b_384_hash", 'string', ['string']),
    "blake2b_512": Module.cwrap("blake2b_512_hash", 'string', ['string']),
    "rmd128": Module.cwrap("rmd128_hash", 'string', ['string']),
    "rmd160": Module.cwrap("rmd160_hash", 'string', ['string']),
    "rmd256": Module.cwrap("rmd256_hash", 'string', ['string']),
    "rmd320": Module.cwrap("rmd320_hash", 'string', ['string']),
    "sha1": Module.cwrap("sha1_hash", 'string', ['string']),
    "sha2_224": Module.cwrap("sha224_hash", 'string', ['string']),
    "sha2_256": Module.cwrap("sha256_hash", 'string', ['string']),
    "sha2_384": Module.cwrap("sha384_hash", 'string', ['string']),
    "sha2_512": Module.cwrap("sha512_hash", 'string', ['string']),
    "sha2_512_224": Module.cwrap("sha512_224_hash", 'string', ['string']),
    "sha2_512_256": Module.cwrap("sha512_256_hash", 'string', ['string']),
    "sha3_224": Module.cwrap("sha3_224_hash", 'string', ['string']),
    "sha3_256": Module.cwrap("sha3_256_hash", 'string', ['string']),
    "sha3_384": Module.cwrap("sha3_384_hash", 'string', ['string']),
    "sha3_512": Module.cwrap("sha3_512_hash", 'string', ['string']),
    "keccak_224": Module.cwrap("keccak_224_hash", 'string', ['string']),
    "keccak_256": Module.cwrap("keccak_256_hash", 'string', ['string']),
    "keccak_384": Module.cwrap("keccak_384_hash", 'string', ['string']),
    "keccak_512": Module.cwrap("keccak_512_hash", 'string', ['string']),
    "whirlpool": Module.cwrap("whirlpool_hash", 'string', ['string']),
}

const output_size = {
    "rmd": [128, 160, 256, 320],
    "blake2s": [128, 160, 224, 256],
    "blake2b": [160, 256, 384, 512],
    "sha2": [224, 256, 384, 512],
    "sha3": [224, 256, 384, 512],
    "keccak": [224, 56, 384, 512],
}

$(document).ready(() => {
    $("#hash-function").on("change", (e)=>{
        console.log(e);
        console.log(output_size[e.target.value]);
        if (output_size[e.target.value]!=undefined) {
            $("#output-size").css("display", "block");
            $("#output-size select").empty();
            output_size[e.target.value].forEach((size, i)=>{
                $("#output-size select").append(`<option value="${size}" ${i==0?'selected':''}>${size} bits</option>`);
            })
        } else {
            $("#output-size").css("display", "none");
        }
    });
    $("#hash").click((e)=>{
        var inputText = $("#input").val();
        var hash_func = $("#hash-function").val();
        var hash_out = output_size[hash_func] ? $("#output-size select").val() : null;
        if (inputText != "") 
        {
            let hash_func_name = `${hash_func}${hash_out ? `_${hash_out}` : ''}`;
            $("#output").val(hash_functions[hash_func_name](inputText));
        }
    });
});

