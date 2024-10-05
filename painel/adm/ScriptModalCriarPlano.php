<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;

$ColunaAcesso = array('PagamentoPagSeguro', 'PagamentoPayPal', 'PagamentoMercadoPago', 'PagamentoContaBancaria');
$VerificarAcesso = VerificarAcesso('pagamentos', $ColunaAcesso);
$PagamentoPagSeguro = $VerificarAcesso[0];
$PagamentoPayPal = $VerificarAcesso[1];
$PagamentoMercadoPago = $VerificarAcesso[2];
$PagamentoContaBancaria = $VerificarAcesso[3];

if( ($PagamentoPagSeguro == 'S') || ($PagamentoPayPal == 'S') || ($PagamentoMercadoPago == 'S') || ($PagamentoContaBancaria == 'S') ){

$CadUser = InfoUser(2);

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
                        	<label class=\"col-md-3 control-label\">".$_TRA['TipodePerfil']."</label>
                            	<div class=\"col-md-9\">                                        
                                	<select class=\"form-control select\" id=\"TipodePerfil\" name=\"TipodePerfil\">
									<option value=\"SAT\">".$_TRA['satelite']."</option>
									<option value=\"CAB\">".$_TRA['cabo']."</option>
                                    </select>
                                 </div>
                        </div>
						
						<div class=\"form-group\">
                        	<label class=\"col-md-3 control-label\">".$_TRA['TipodePlano']."</label>
                            	<div class=\"col-md-9\">                                        
                                	<select class=\"form-control select\" id=\"TipodePlano\" name=\"TipodePlano\">
									<option value=\"N\">".$_TRA['normal']."</option>
									<option value=\"P\">".$_TRA['prepago']."</option>
                                    </select>
                                 </div>
                        </div>
						
						<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">Nome do Plano</label>
                            <div class=\"col-md-9\">
                                <input id=\"nomeplano\" name=\"nomeplano\" type=\"text\" class=\"validate[required] form-control\">
                            </div>
                        </div>
             
                        <div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".ucfirst($_TRA['dias'])."</label>
                            <div class=\"col-md-9\">
                                <input id=\"Dias\" name=\"Dias\" type=\"text\" class=\"validate[required] form-control\">
                            </div>
                        </div>
						
						<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['Valor']."</label>
                            <div class=\"col-md-9\">
                                <input id=\"EditarValorCobrado\" name=\"EditarValorCobrado\" type=\"text\" class=\"validate[required] form-control\">
                            </div>
                        </div>
						
						<div class=\"form-group\" id=\"StatusTipo\"></div>
						
						<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['Perfil']."</label>
                            <div class=\"col-md-9\">
							".PerfilCriarPlano($CadUser)."
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

<script type="text/javascript" src="js/jquery.maskMoney.js"></script>
<script type="text/javascript" src="js/jquery.maskMoney<?php echo Idioma(2); ?>.js"></script>

<script>
$("#EditarModal").modal("show");

$(function(){  
 $("button.SalvarForma").click(function() { 
		
		var Data = $(".AdicionarFormaPag").serialize();
		
		$('#StatusModal').html("<center><img src=\"img/owl/AjaxLoader.gif\"><br><br></center>");
		
		$.post('EnviarAdicionarCriarPlano.php', Data, function(resposta) {
				$("#StatusModal").html('');
				$("#StatusGeral").append(resposta);
		});
	});
});

$(function(){
	$(".AdicionarFormaPag select[name=TipodePlano]").change(function(){
		
		var id = $(this).val();
		
		if(id == "N"){
			$("#StatusTipo").html('');
		}
		else{
			var operacao = '<?php echo "<label class=\"col-md-3 control-label\">".$_TRA['Quantidade']."</label><div class=\"col-md-9\"><input id=\"Quantidade\" name=\"Quantidade\" type=\"text\" class=\"validate[required] form-control\"></div>"; ?>';
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