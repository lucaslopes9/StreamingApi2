jQuery(function($){
	var ExecutarValor = function(){
			$('#EditarValorCobrado').maskMoney({
				prefix:"R$ ",
				decimal:",",
				thousands:"."
			});
			$('#ValorCobrado').maskMoney({
				prefix:"R$ ",
				decimal:",",
				thousands:"."
			});
			$('#EditarValorCobradoCab').maskMoney({
				prefix:"R$ ",
				decimal:",",
				thousands:"."
			});
	}  
	
	ExecutarValor();
});