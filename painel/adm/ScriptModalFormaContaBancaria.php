<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;

$ColunaAcesso = array('PagamentoContaBancaria');
$VerificarAcesso = VerificarAcesso('pagamentos', $ColunaAcesso);
$PagamentoContaBancaria = $VerificarAcesso[0];
 
if($PagamentoContaBancaria == 'S'){

echo "<div class=\"modal animated fadeIn\" id=\"EditarModal\" tabindex=\"-1\" role=\"dialog\" aria-labelledby=\"smallModalHead\" aria-hidden=\"true\">
            <div class=\"modal-dialog\">
                <div class=\"modal-content\">
                    <div class=\"modal-header\">
                        <button type=\"button\" class=\"close\" data-dismiss=\"modal\"><span aria-hidden=\"true\">&times;</span><span class=\"sr-only\">".$_TRA['fechar']."</span></button>
                        <h4 class=\"modal-title\" id=\"smallModalHead\">".$_TRA['Adicionar']."</h4>
                    </div>
                    <div class=\"modal-body form-horizontal form-group-separated\">     
						<form id=\"validate\" role=\"form\" class=\"AdicionarFormaPag form-horizontal\" action=\"javascript:MDouglasMS();\">
                        
						<div class=\"form-group\">
                        	<label class=\"col-md-3 control-label\">".$_TRA['Tipo']."</label>
                            	<div class=\"col-md-9\">                                        
                                	<select class=\"form-control select\" id=\"Tipo\" name=\"Tipo\">
									<option value=\"C\">".$_TRA['ContaCorrente']."</option>
									<option value=\"P\">".$_TRA['ContaPoupanca']."</option>
                                    </select>
                                 </div>
                        </div>
						
						<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['Banco']."</label>
                            <div class=\"col-md-9\">
                                <input id=\"Banco\" name=\"Banco\" type=\"text\" class=\"validate[required] form-control\">
                            </div>
                        </div>
						
						<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['Agencia']."</label>
                            <div class=\"col-md-9\">
                                <input id=\"Agencia\" name=\"Agencia\" type=\"text\" class=\"validate[required] form-control\">
                            </div>
                        </div>
						
						<div id=\"StatusTipo\" class=\"form-group\"></div>
						
						<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['Conta']."</label>
                            <div class=\"col-md-9\">
                                <input id=\"Conta\" name=\"Conta\" type=\"text\" class=\"validate[required] form-control\">
                            </div>
                        </div>
						
						<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['Favorecido']."</label>
                            <div class=\"col-md-9\">
                                <input id=\"Favorecido\" name=\"Favorecido\" type=\"text\" class=\"validate[required] form-control\">
                            </div>
                        </div>
						
						</form>
                    </div>
                    <div class=\"modal-footer\">
						<div id=\"StatusModal\"></div>
                        <button type=\"button\" class=\"SalvarForma btn btn-danger\">".$_TRA['Adicionar']."</button>
                        <button type=\"button\" class=\"btn btn-default\" data-dismiss=\"modal\">".$_TRA['fechar']."</button>
                    </div>
                </div>
            </div>
        </div>";
?>

<script type='text/javascript' src='js/plugins/validationengine/languages/jquery.validationEngine<?php echo Idioma(2); ?>.js'></script>
<script type='text/javascript' src='js/plugins/validationengine/jquery.validationEngine.js'></script>

<script type="text/javascript" src="js/plugins/bootstrap/bootstrap-select.js"></script>

<!-- START TEMPLATE -->    
<?php include_once("js/settings".Idioma(2).".php"); ?>     
<script type="text/javascript" src="js/plugins.js"></script>      
<!-- END TEMPLATE -->

<script>
$("#EditarModal").modal("show");

$(function(){  
 $("button.SalvarForma").click(function() { 
		
		var Data = $(".AdicionarFormaPag").serialize();
		
		$('#StatusModal').html("<center><img src=\"img/owl/AjaxLoader.gif\"><br><br></center>");
		
		$.post('EnviarAdicionarFormaContaBancaria.php', Data, function(resposta) {
				$("#StatusModal").html('');
				$("#StatusGeral").append(resposta);
		});
	});
});

$(function(){
	$(".AdicionarFormaPag select[name=Tipo]").change(function(){
		
		var id = $(this).val();
		
		if(id == "C"){
			$("#StatusTipo").html('');
		}
		else{
			var operacao = '<?php echo "<label class=\"col-md-3 control-label\">".$_TRA['Operacao']."</label><div class=\"col-md-9\"><input id=\"Operacao\" name=\"Operacao\" type=\"text\" class=\"validate[required] form-control\"></div>"; ?>';
			$("#StatusTipo").html(operacao);
		}
		
	});
});
</script>

   
<?php  
}else{
	echo Redirecionar('index.php');
}
}else{
	echo Redirecionar('login.php');
}	
?>