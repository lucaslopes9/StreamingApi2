<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;

$ColunaAdmin = array('RevAdicionar');
$VerificarAcesso = VerificarAcesso('rev', $ColunaAdmin);
$AdminAdicionar = $VerificarAcesso[0];
$CadUser = InfoUser(2);
$VerificarInfoPre = VerificarInfoPre();
 
if($AdminAdicionar == 'S'){
	
if ($_SERVER['REQUEST_METHOD'] == 'POST') {

echo "<div class=\"modal animated fadeIn\" id=\"EditarAdmin\" tabindex=\"-1\" role=\"dialog\" aria-labelledby=\"smallModalHead\" aria-hidden=\"true\">
            <div class=\"modal-dialog\">
                <div class=\"modal-content\">
                    <div class=\"modal-header\">
                        <button type=\"button\" class=\"close\" data-dismiss=\"modal\"><span aria-hidden=\"true\">&times;</span><span class=\"sr-only\">".$_TRA['fechar']."</span></button>
                        <h4 class=\"modal-title\" id=\"smallModalHead\">".$_TRA['Adicionar']."</h4>
                    </div>
                    <div class=\"modal-body form-horizontal form-group-separated\">     
						<form id=\"validate\" role=\"form\" class=\"AdicionarRevendedor form-horizontal\" action=\"javascript:MDouglasMS();\">
						
						<div class=\"form-group\">
                        	<label class=\"col-md-3 control-label\">".$_TRA['ed']."</label>
                            	<div class=\"col-md-9\">                                        
   								<div style=\"border:0px; padding: 0px 0px 5px 0px;\" class=\"col-md-5\"><label class=\"check\"><input name=\"EnviarEmail\" id=\"EnviarEmail\" type=\"checkbox\" class=\"icheckbox\" /> ".$_TRA['email']."</label></div>
								<div style=\"border:0px; padding: 0px 0px 5px 0px;\" class=\"col-md-5\"><label class=\"check\"><input name=\"EnviarSMS\" id=\"EnviarSMS\" type=\"checkbox\" class=\"icheckbox\" /> ".$_TRA['sms']."</label></div>
                                 </div>
                        </div>
						
						<div class=\"form-group\">
                        	<label class=\"col-md-3 control-label\">Enviar com</label>
                            	<div class=\"col-md-9\">                                        
                                	<select class=\"form-control select\" id=\"EnviarCOM\" name=\"EnviarCOM\">";
									
									$CadUser = InfoUser(2);
									$bloqueado = "N";
									$SQLEnviarC1 = "SELECT id, email FROM email_adicionar WHERE bloqueado = :bloqueado AND CadUser = :CadUser";
									$SQLEnviarC1 = $painel_geral->prepare($SQLEnviarC1);
									$SQLEnviarC1->bindParam(':bloqueado', $bloqueado, PDO::PARAM_STR);
									$SQLEnviarC1->bindParam(':CadUser', $CadUser, PDO::PARAM_STR);
									$SQLEnviarC1->execute();
									$TotalEnviarC = count($SQLEnviarC1->fetchAll());
	
									if($TotalEnviarC > 0){
										$SQLEnviarC1->execute();
										$LnEnviarC = $SQLEnviarC1->fetch();
										echo "<option value=\"".$LnEnviarC['id']."\">".$LnEnviarC['email']."</option>";
									}
	
									$bloqueado = "S";
									$SQLEnviarC1 = "SELECT id, email FROM email_adicionar WHERE bloqueado = :bloqueado AND CadUser = :CadUser";
									$SQLEnviarC1 = $painel_geral->prepare($SQLEnviarC1);
									$SQLEnviarC1->bindParam(':bloqueado', $bloqueado, PDO::PARAM_STR);
									$SQLEnviarC1->bindParam(':CadUser', $CadUser, PDO::PARAM_STR);
									$SQLEnviarC1->execute();
									while($LnEnviarC = $SQLEnviarC1->fetch()){
										echo "<option value=\"".$LnEnviarC['id']."\">".$LnEnviarC['email']."</option>";
									}
									
									
									
                                    echo "</select>
                                 </div>
                        </div>
						
						 <div class=\"form-group\">
                        	<label class=\"col-md-3 control-label\">".$_TRA['vpe']."</label>
                            	<div class=\"col-md-9\">                                        
                                	<select class=\"form-control select\" id=\"EditarPorEmail\" name=\"EditarPorEmail\">
									<option value=\"S\">".$_TRA['sim']."</option>
                                                                        <option value=\"N\">".$_TRA['nao']."</option>
                                    </select>
                                 </div>
                        </div>
						
						<div class=\"form-group\">
                        	<label class=\"col-md-3 control-label\">".$_TRA['vps']."</label>
                            	<div class=\"col-md-9\">                                        
                                	<select class=\"form-control select\" id=\"EditarPorSMS\" name=\"EditarPorSMS\">
									<option value=\"N\">".$_TRA['nao']."</option>
									<option value=\"S\">".$_TRA['sim']."</option>
                                    </select>
                                 </div>
                        </div>
						
                        <div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['nome']."</label>
                            <div class=\"col-md-9\">
                                <input pattern=\"[A-Za-z]\" onkeypress=\"sem_acento(event)\" onkeydown =\"onKeyDown()\" id=\"EditarNome\" name=\"EditarNome\" type=\"text\" class=\"form-control\">
                            </div>
                        </div>
                        <div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['sobrenome']."</label>
                            <div class=\"col-md-9\">
                                <input pattern=\"[A-Za-z]\" onkeypress=\"sem_acento(event)\" onkeydown =\"onKeyDown()\" id=\"EditarSobrenome\" name=\"EditarSobrenome\" type=\"text\" class=\"form-control\">
                            </div>
                        </div>
                        <div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['Usuario']."</label>
                            <div class=\"col-md-9\">
                                <input pattern=\"[A-Za-z]\" onkeypress=\"sem_acento(event)\" onkeydown =\"onKeyDown()\" id=\"EditarUsuario\" name=\"EditarUsuario\" type=\"text\" class=\"validate[required] form-control\">
                            </div>
                        </div>
						<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['Senha']."</label>
                            <div class=\"col-md-9\">
                                <input pattern=\"[A-Za-z]\" onkeypress=\"sem_acento(event)\" onkeydown =\"onKeyDown()\" id=\"EditarUsuario\" name=\"EditarSenha\" type=\"text\" class=\"validate[required] form-control\">
                            </div>
                        </div>
						<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['email']."</label>
                            <div class=\"col-md-9\">
                                <input pattern=\"[A-Za-z]\" onkeypress=\"sem_acento(event)\" onkeydown =\"onKeyDown()\" id=\"EditarEmail\" name=\"EditarEmail\" type=\"text\" class=\"validate[custom[email]] form-control\">
                            </div>
                        </div>
						<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['celular']."</label>
                            <div class=\"col-md-9\">
                                <input onkeypress=\"sem_acento(event)\" id=\"EditarCelular\" name=\"EditarCelular\" type=\"text\" class=\"mask_phone_ext validate[custom[phone]] form-control\">
                            </div>
                        </div>
						<div class=\"form-group\">
                        	<label class=\"col-md-3 control-label\">".$_TRA['ldt']."</label>
                            	<div class=\"col-md-9\">
                                <input pattern=\"[A-Za-z]\" onkeypress=\"sem_acento(event)\" onkeydown =\"onKeyDown()\" type=\"text\" name=\"EditarLimiteTeste\" id=\"EditarLimiteTeste\" class=\"form-control spinner_default\" value=\"0\"/>
                                </div>
                        </div>
						<div class=\"form-group\">
                        	<label class=\"col-md-3 control-label\">Limite de Usuário</label>
                            	<div class=\"col-md-9\">
                                <input pattern=\"[A-Za-z]\" onkeypress=\"sem_acento(event)\" onkeydown =\"onKeyDown()\" type=\"text\" name=\"EditarLimiteUser\" id=\"EditarLimiteUser\" class=\"form-control spinner_default\" value=\"0\"/>
                                </div>
                        </div>
						";
						
						if($VerificarInfoPre[0] == "N"){
						echo "<div class=\"form-group\">
                        	<label class=\"col-md-3 control-label\">".$_TRA['prepago']."</label>
                            	<div class=\"col-md-9\">                                        
                                	<select class=\"form-control select\" id=\"EditarPrePago\" name=\"EditarPrePago\">
									<option value=\"N\">".$_TRA['nao']."</option>
									<option value=\"S\">".$_TRA['sim']."</option>
                                    </select>
                                 </div>
                        </div>";
						}
						
						if($VerificarInfoPre[0] == "N"){
							
						echo "<div class=\"form-group\" id=\"StatusPre\">";
						
						echo "<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['DataPremio']."</label>
                            <div class=\"col-md-9\">
								<div class=\"input-group date\">
                                	<input onkeypress=\"sem_acento(event)\" type=\"text\" id=\"dp-3\" name=\"EditarPremium\" class=\"form-control\" />
                                    <span class=\"input-group-addon\"><span class=\"glyphicon glyphicon-calendar\"></span></span>
                            	</div>
                            </div>
						</div>";
						
							
						echo "<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['valorsat']."</label>
                            <div class=\"col-md-9\">
                                <input pattern=\"[A-Za-z]\" onkeypress=\"sem_acento(event)\" onkeydown =\"onKeyDown()\" id=\"EditarValorCobrado\" name=\"EditarValorCobrado\" type=\"text\" class=\"form-control\">
                            </div>
                        </div>
						
						<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['valorcab']."</label>
                            <div class=\"col-md-9\">
                                <input pattern=\"[A-Za-z]\" onkeypress=\"sem_acento(event)\" onkeydown =\"onKeyDown()\" id=\"EditarValorCobradoCab\" name=\"EditarValorCobradoCab\" type=\"text\" class=\"form-control\">
                            </div>
                        </div>
							
                        </div>";
						
						}
						else{
						
						echo "
						<div class=\"form-group\">
    						<label class=\"col-md-3 control-label\">".$_TRA['Cota']."</label>
        						<div class=\"col-md-9\">
           							<input pattern=\"[A-Za-z]\" onkeypress=\"sem_acento(event)\" onkeydown =\"onKeyDown()\" id=\"EditarCota\" name=\"EditarCota\" type=\"text\" class=\"form-control\">
            					</div>
    					</div>
						
						<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['valorsat']."</label>
                            <div class=\"col-md-9\">
                                <input pattern=\"[A-Za-z]\" onkeypress=\"sem_acento(event)\" onkeydown =\"onKeyDown()\" id=\"EditarValorCobrado\" name=\"EditarValorCobrado\" type=\"text\" class=\"form-control\">
                            </div>
                        </div>
						
						<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['valorcab']."</label>
                            <div class=\"col-md-9\">
                                <input pattern=\"[A-Za-z]\" onkeypress=\"sem_acento(event)\" onkeydown =\"onKeyDown()\" id=\"EditarValorCobradoCab\" name=\"EditarValorCobradoCab\" type=\"text\" class=\"form-control\">
                            </div>
                        </div>";
							
						}
						
						echo "<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['obs']."</label>
                            <div class=\"col-md-9\">
							    <textarea pattern=\"[A-Za-z]\" onkeypress=\"sem_acento(event)\" onkeydown =\"onKeyDown()\" rows=\"10\" class=\"form-control\" id=\"obs\" name=\"obs\"></textarea>
                            </div>
                        </div>";
						
						echo "<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['Perfil']."</label>
                            <div class=\"col-md-9\">
							".PerfilAdminEditar($CadUser, 0, 2)."
                            </div>
                        </div>
						
						
						</form>
                    </div>
                    <div class=\"modal-footer\">
						<div id=\"StatusModal\"></div>
                        <button type=\"button\" class=\"SalvarAdicionar btn btn-danger\">".$_TRA['Adicionar']."</button>
                        <button type=\"button\" class=\"btn btn-default\" data-dismiss=\"modal\">".$_TRA['fechar']."</button>
                    </div>
                </div>
            </div>
        </div>";
?>
<script type='text/javascript' src='js/plugins/validationengine/languages/jquery.validationEngine<?php echo Idioma(2); ?>.js'></script>
<script type='text/javascript' src='js/plugins/validationengine/jquery.validationEngine.js'></script>
<script type='text/javascript' src='js/plugins/maskedinput/jquery.maskedinput.min.js'></script>

<script type="text/javascript" src="js/plugins/bootstrap/bootstrap-select.js"></script>

<script type="text/javascript" src="js/plugins/bootstrap/bootstrap-datepicker.js"></script>
<script type="text/javascript" src="js/plugins/bootstrap/locales/bootstrap-datepicker<?php echo Idioma(2); ?>.js"></script>

<!-- START TEMPLATE -->   
<?php include_once("js/settings".Idioma(2).".php"); ?>    
<script type="text/javascript" src="js/plugins.js"></script>    
<!-- END TEMPLATE -->
<script language="javascript">
function onKeyDown() {
  // current pressed key
  var pressedKey = String.fromCharCode(event.keyCode).toLowerCase();
  if (event.ctrlKey && (pressedKey == "c" || 
                        pressedKey == "x" ||
                        pressedKey == "v")) {
    // disable key press porcessing
    event.returnValue = false;
  }
} // onKeyDown
</script>


<script language=JavaScript>
<!--
function desabilitar(){
    alert ("Função desabilitada.\n\nDesculpe o incômodo.")
    return false
}
document.oncontextmenu=desabilitar
// -->
</script> 

<script language="javascript">
function sem_acento(e,args)
{		
  var evt = (document.all)? event.keyCode : e.charCode;
  var valid_chars = '0123456789abcdefghijlmnopqrstuvxzwykABCDEFGHIJLMNOPQRSTUVXZWYK@.-_ '+args;	
  var chr= String.fromCharCode(evt);	// pegando a tecla digitada
  if (valid_chars.indexOf(chr)<0){
    e.preventDefault();
    alert('caracter invalido');
  }
}
</script>

<script type="text/javascript" src="js/jquery.maskMoney.js"></script>
<script type="text/javascript" src="js/jquery.maskMoney<?php echo Idioma(2); ?>.js"></script>      
<script>
$("#EditarAdmin").modal("show");

$(function(){  
 $("button.SalvarAdicionar").click(function() { 
 
 		var Data = $(".AdicionarRevendedor").serialize();
		
		$('#StatusModal').html("<center><img src=\"img/owl/AjaxLoader.gif\"><br><br></center>");
		
		$.post('EnviarAdicionarRev.php', Data, function(resposta) {
				$("#StatusModal").html('');
				$("#StatusGeral").append(resposta);
		});
	});
});

$(function(){
	$(".AdicionarRevendedor select[name=EditarPrePago]").change(function(){
		
		var id = $(this).val();
		
		$.post('ExibirSelectRev.php', {id: id}, function(resposta) {
				$("#StatusPre").html('');
				$("#StatusPre").html(resposta);
		});
	});
});

$(function(){
        //Spinner
        $(".spinner_default").spinner({
			min: 0,
			step: 1, 
			numberFormat: "n"
		});                
        //End spinner
});
</script>

<?php  
}
}else{
	echo Redirecionar('index.php');
}
}else{
	echo Redirecionar('login.php');
}	
?>