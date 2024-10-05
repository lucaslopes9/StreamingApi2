<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;

//Status do Servidor
$ColunaStatusServer = array('OpcoesBackup');
$VerificarStatusServer = VerificarAcesso('opcoes', $ColunaStatusServer);
$OpcoesBackup = $VerificarStatusServer[0];

if($OpcoesBackup == 'S'){
	
	$SQLUrlT = "SELECT nome FROM server";
	$SQLUrlT = $painel_geral->prepare($SQLUrlT);
	$SQLUrlT->execute();
	$LnUrlT = $SQLUrlT->fetch();
	
	$nome = empty($LnUrlT['nome']) ? "" : $LnUrlT['nome'];
	
echo "<div class=\"modal animated fadeIn\" id=\"EditarAdmin\" tabindex=\"-1\" role=\"dialog\" aria-labelledby=\"smallModalHead\" aria-hidden=\"true\">
            <div class=\"modal-dialog\">
                <div class=\"modal-content\">
                    <div class=\"modal-header\">
                        <button type=\"button\" class=\"close\" data-dismiss=\"modal\"><span aria-hidden=\"true\">&times;</span><span class=\"sr-only\">".$_TRA['fechar']."</span></button>
                        <h4 class=\"modal-title\" id=\"smallModalHead\">Backup Automatizado</h4>
                    </div>
                    <div class=\"modal-body form-horizontal form-group-separated\">     
						<form id=\"validate\" role=\"form\" class=\"ConfigTeste form-horizontal\" action=\"javascript:MDouglasMS();\">
						
						<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">Nome</label>
                            <div class=\"col-md-9\">
                                <input id=\"Nome\" name=\"Nome\" type=\"text\" placeholder=\"Em branco não será alterado!\" value=\"".$nome."\" class=\"validate[required] form-control\">
                            </div>
                        </div>
						
						<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">IP</label>
                            <div class=\"col-md-9\">
                                <input id=\"IP\" name=\"IP\" type=\"text\" placeholder=\"Em branco não será alterado!\" class=\"validate[required] form-control\">
                            </div>
                        </div>
						
						<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">Porta</label>
                            <div class=\"col-md-9\">
                                <input id=\"porta\" name=\"porta\" type=\"text\" placeholder=\"Em branco não será alterado!\" class=\"validate[required] form-control\">
                            </div>
                        </div>
						
						<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">Usuário</label>
                            <div class=\"col-md-9\">
                                <input id=\"user\" name=\"user\" type=\"text\" placeholder=\"Em branco não será alterado!\" class=\"validate[required] form-control\">
                            </div>
                        </div>
						
						<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">Senha</label>
                            <div class=\"col-md-9\">
                                <input id=\"senha\" name=\"senha\" type=\"text\" placeholder=\"Em branco não será alterado!\" class=\"validate[required] form-control\">
                            </div>
                        </div>
						
						</form>
                    </div>
                    <div class=\"modal-footer\">
						<div id=\"StatusModal\"></div>
                        <button type=\"button\" class=\"SalvarConfigTeste btn btn-danger\">Salvar</button>
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
$("#EditarAdmin").modal("show");

$(function(){  
 $("button.SalvarConfigTeste").click(function() { 
 
 		var Data = $(".ConfigTeste").serialize();
		
		panel_refresh($(".ConfigTeste"));
				
		$.post('EnviarConfigBackupServer.php', Data, function(resposta) {
				setTimeout(panel_refresh($(".ConfigTeste")),500);
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