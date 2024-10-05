<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;
	
$ColunaAcesso = array('EmailModeloPreferencias');
$VerificarAcesso = VerificarAcesso('email_modelo', $ColunaAcesso);
$EmailModeloPreferencias = $VerificarAcesso[0];
 
if($EmailModeloPreferencias == 'S'){

echo "<div class=\"modal animated fadeIn\" id=\"EditarModal\" tabindex=\"-1\" role=\"dialog\" aria-labelledby=\"smallModalHead\" aria-hidden=\"true\">
            <div class=\"modal-dialog\">
                <div class=\"modal-content\">
                    <div class=\"modal-header\">
                        <button type=\"button\" class=\"close\" data-dismiss=\"modal\"><span aria-hidden=\"true\">&times;</span><span class=\"sr-only\">".$_TRA['fechar']."</span></button>
                        <h4 class=\"modal-title\" id=\"smallModalHead\">".$_TRA['Preferencias']."</h4>
                    </div>
                    <div class=\"modal-body form-horizontal form-group-separated\">     
						<form id=\"validate\" role=\"form\" class=\"AdicionarPref form-horizontal\" action=\"javascript:MDouglasMS();\">
						
						<div class=\"form-group\">
                        	<label class=\"col-md-3 control-label\">".$_TRA['da']."</label>
                            <div class=\"col-md-9\">                                        
                            <select class=\"form-control select\" id=\"Pref1\" name=\"Pref1\">
							".SelecionarModeloPreferencias('Painel','DadosDeAcesso')."
							</select>
                            </div>
                        </div>
						
						<div class=\"form-group\">
                        	<label class=\"col-md-3 control-label\">".$_TRA['dat']."</label>
                            <div class=\"col-md-9\">                                        
                            <select class=\"form-control select\" id=\"Pref2\" name=\"Pref2\">
							".SelecionarModeloPreferencias('Painel','DadosDeAcessoTeste')."
							</select>
                            </div>
                        </div>
						
						<div class=\"form-group\">
                        	<label class=\"col-md-3 control-label\">".$_TRA['Vencimento']."</label>
                            <div class=\"col-md-9\">                                        
                            <select class=\"form-control select\" id=\"Pref3\" name=\"Pref3\">
							".SelecionarModeloPreferencias('Painel','Vencimento')."
							</select>
                            </div>
                        </div>
						
						<div class=\"form-group\">
                        	<label class=\"col-md-3 control-label\">".$_TRA['Renovacao']."</label>
                            <div class=\"col-md-9\">                                        
                            <select class=\"form-control select\" id=\"Pref4\" name=\"Pref4\">
							".SelecionarModeloPreferencias('Painel','Renovacao')."
							</select>
                            </div>
                        </div>
						
	
						</form>
                    </div>
                    <div class=\"modal-footer\">
						<div id=\"StatusModal\"></div>
                        <button type=\"button\" class=\"SalvarModelo btn btn-danger\">".$_TRA['salvar']."</button>
                        <button type=\"button\" class=\"btn btn-default\" data-dismiss=\"modal\">".$_TRA['fechar']."</button>
                    </div>
                </div>
            </div>
        </div>";
?>

<script type='text/javascript' src='js/plugins/validationengine/languages/jquery.validationEngine<?php echo Idioma(2); ?>.js'></script>
<script type='text/javascript' src='js/plugins/validationengine/jquery.validationEngine.js'></script>
<script type="text/javascript" src="js/plugins/bootstrap/bootstrap-select.js"></script>
<script type='text/javascript' src='js/plugins.js'></script>

<script>
$("#EditarModal").modal("show");

$(function(){  
 $("button.SalvarModelo").click(function() { 
 		
		var Data = $(".AdicionarPref").serialize();
				 		
		$('#StatusModal').html("<center><img src=\"img/owl/AjaxLoader.gif\"><br><br></center>");
		
		$.post('EnviarPrefEmailModelo.php', Data, function(resposta) {
				$("#StatusModal").html('');
				$("#StatusGeral").append(resposta);
		});
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