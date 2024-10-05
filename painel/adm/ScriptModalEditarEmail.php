<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;
	
$ColunaAcesso = array('EmailadicionarEditar');
$VerificarAcesso = VerificarAcesso('email_adicionar', $ColunaAcesso);
$EmailadicionarEditar = $VerificarAcesso[0];
 
if($EmailadicionarEditar == 'S'){
	
$id = (isset($_POST['id'])) ? $_POST['id'] : '';
	
$CadUser = InfoUser(2);
$SQL = "SELECT servidor, exibicao, email, usuario, senha, SMTPSecure, Host, Port, bloqueado FROM email_adicionar WHERE CadUser = :CadUser AND id = :id";
$SQL = $painel_geral->prepare($SQL);
$SQL->bindParam(':CadUser', $CadUser, PDO::PARAM_STR); 
$SQL->bindParam(':id', $id, PDO::PARAM_INT);
$SQL->execute();
$Ln = $SQL->fetch();
	
echo "<div class=\"modal animated fadeIn\" id=\"EditarModal\" tabindex=\"-1\" role=\"dialog\" aria-labelledby=\"smallModalHead\" aria-hidden=\"true\">
            <div class=\"modal-dialog\">
                <div class=\"modal-content\">
                    <div class=\"modal-header\">
                        <button type=\"button\" class=\"close\" data-dismiss=\"modal\"><span aria-hidden=\"true\">&times;</span><span class=\"sr-only\">".$_TRA['fechar']."</span></button>
                        <h4 class=\"modal-title\" id=\"smallModalHead\">".$_TRA['editar']." (".$Ln['email'].")</h4>
                    </div>
                    <div class=\"modal-body form-horizontal form-group-separated\">     
						<form id=\"validate\" role=\"form\" class=\"EditarEmail form-horizontal\" action=\"javascript:MDouglasMS();\">
						
						<div class=\"form-group\">
                        	<label class=\"col-md-3 control-label\">".$_TRA['Servidor']."</label>
                            	<div class=\"col-md-9\">                                        
                                	<select class=\"form-control select\" id=\"EmailPersonalizado\" name=\"EmailPersonalizado\">";
										
										if($Ln['servidor'] == 'Gmail'){
                                    	echo "
										<option value=\"Gmail\">Gmail</option>
										<option value=\"Hotmail\">Hotmail</option>
										<option value=\"Yahoo\">Yahoo</option>
										<option value=\"Bol\">Bol</option>
										<option value=\"Aol\">Aol</option>
										<option value=\"Personalizado\">Personalizado</option>
										";
										}
										elseif($Ln['servidor'] == 'Hotmail'){
                                    	echo "
										<option value=\"Hotmail\">Hotmail</option>
										<option value=\"Yahoo\">Yahoo</option>
										<option value=\"Bol\">Bol</option>
										<option value=\"Aol\">Aol</option>
										<option value=\"Gmail\">Gmail</option>
										<option value=\"Personalizado\">Personalizado</option>
										";
										}
										elseif($Ln['servidor'] == 'Yahoo'){
                                    	echo "
										<option value=\"Yahoo\">Yahoo</option>
										<option value=\"Bol\">Bol</option>
										<option value=\"Aol\">Aol</option>
										<option value=\"Gmail\">Gmail</option>
										<option value=\"Hotmail\">Hotmail</option>
										<option value=\"Personalizado\">Personalizado</option>
										";
										}
										elseif($Ln['servidor'] == 'Bol'){
                                    	echo "
										<option value=\"Bol\">Bol</option>
										<option value=\"Aol\">Aol</option>
										<option value=\"Gmail\">Gmail</option>
										<option value=\"Hotmail\">Hotmail</option>
										<option value=\"Yahoo\">Yahoo</option>
										<option value=\"Personalizado\">Personalizado</option>
										";
										}
										elseif($Ln['servidor'] == 'Aol'){
                                    	echo "
										<option value=\"Aol\">Aol</option>
										<option value=\"Gmail\">Gmail</option>
										<option value=\"Hotmail\">Hotmail</option>
										<option value=\"Yahoo\">Yahoo</option>
										<option value=\"Bol\">Bol</option>
										<option value=\"Personalizado\">Personalizado</option>
										";
										}
										else{
										echo "
										<option value=\"Personalizado\">Personalizado</option>
										<option value=\"Gmail\">Gmail</option>
										<option value=\"Hotmail\">Hotmail</option>
										<option value=\"Yahoo\">Yahoo</option>
										<option value=\"Bol\">Bol</option>
										<option value=\"Aol\">Aol</option>
										";	
										}
										
                                    echo "</select>
                                 </div>
                        </div>
						
                        <div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['Exibicao']."</label>
                            <div class=\"col-md-9\">
                                <input id=\"EmailExibicao\" name=\"EmailExibicao\" value=\"".$Ln['exibicao']."\" type=\"text\" class=\"validate[required] form-control\">
                            </div>
                        </div>
                        <div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['email']."</label>
                            <div class=\"col-md-9\">
                                <input id=\"EmailEmail\" name=\"EmailEmail\" value=\"".$Ln['email']."\" type=\"text\" class=\"validate[required,custom[email]] form-control\">
                            </div>
                        </div>
						
						<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['Usuario']."</label>
                            <div class=\"col-md-9\">
                                <input id=\"EmailUsuario\" name=\"EmailUsuario\" value=\"".$Ln['usuario']."\" type=\"text\" class=\"validate[required] form-control\">
                            </div>
                        </div>
						
                        <div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['Senha']."</label>
                            <div class=\"col-md-9\">
                                <input id=\"EmailSenha\" name=\"EmailSenha\" type=\"text\" class=\"validate[required] form-control\">
                            </div>
                        </div>
						
						<div class=\"form-group\">
                        	<label class=\"col-md-3 control-label\">".$_TRA['SMTPSecure']."</label>
                            	<div class=\"col-md-9\">                                        
                                	<select class=\"form-control select\" id=\"EmailSMTP\" name=\"EmailSMTP\">";
										
										if($Ln['SMTPSecure'] == "ssl"){
                                    	echo "<option value=\"ssl\">SSL</option>
										<option value=\"tls\">TLS</option>";
										}
										elseif($Ln['SMTPSecure'] == "tls"){
                                    	echo "<option value=\"tls\">TLS</option>
										<option value=\"ssl\">SSL</option>";
										}
										else{
										echo "<option value=\"ssl\">SSL</option>
										<option value=\"tls\">TLS</option>";
										}
                                     
									 echo "</select>
									 <span id=\"StatusEmailSMTP\"></span>
                                 </div>
                        </div>
						
						<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['ServidorSMTP']."</label>
                            <div class=\"col-md-9\">
                                <input id=\"EmailServidor\" value=\"".$Ln['Host']."\" name=\"EmailServidor\" type=\"text\" class=\"validate[required] form-control\">
                            </div>
                        </div>
						
						<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['Porta']."</label>
                            <div class=\"col-md-9\">
                                <input id=\"EmailPorta\" value=\"".$Ln['Port']."\" name=\"EmailPorta\" type=\"text\" class=\"validate[required,custom[integer],custom[number]] form-control\">
                            </div>
                        </div>
						
						<input type=\"hidden\" id=\"EmailID\" name=\"EmailID\" value=\"".$id."\">

						</form>
                    </div>
                    <div class=\"modal-footer\">
						<div id=\"StatusModal\"></div>
                        <button type=\"button\" class=\"EditarEmail btn btn-danger\">".$_TRA['editar']."</button>
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
 $("button.EditarEmail").click(function() { 
 
		 var Data = $(".EditarEmail").serialize();
		
		$('#StatusModal').html("<center><img src=\"img/owl/AjaxLoader.gif\"><br><br></center>");
		
		$.post('EnviarEmailEditar.php', Data, function(resposta) {
				$("#StatusModal").html('');
				$("#StatusGeral").append(resposta);
		});
	});
});

$(function(){
	$("select[name=EmailPersonalizado]").change(function(){
		var valor = $(this).val();
		var host = '';
		var SMTPSecure = '';
		var SMTPSecureRem = '';
		var Porta = '';
		var EmailSMTP = '';
		
		if(valor == 'Gmail'){
			host = 'smtp.gmail.com';
			SMTPSecure = 'ssl';
			SMTPSecureRem = 'tls';
			Porta = '465';
			EmailSMTP = '<input type="hidden" id="EmailSMTP" name="EmailSMTP" value="'+SMTPSecure+'">';
		}
		else if(valor == 'Hotmail'){
			host = 'smtp.live.com';
			SMTPSecure = 'tls';
			SMTPSecureRem = 'ssl';
			Porta = '25';
			EmailSMTP = '<input type="hidden" id="EmailSMTP" name="EmailSMTP" value="'+SMTPSecure+'">';
		}
		else if(valor == 'Yahoo'){
			host = 'smtp.mail.yahoo.com.br';
			SMTPSecure = 'tls';
			SMTPSecureRem = 'ssl';
			Porta = '587';
			EmailSMTP = '<input type="hidden" id="EmailSMTP" name="EmailSMTP" value="'+SMTPSecure+'">';
		}
		else if(valor == 'Bol'){
			host = 'smtps.bol.com.br';
			SMTPSecure = 'tls';
			SMTPSecureRem = 'ssl';
			Porta = '587 ';
			EmailSMTP = '<input type="hidden" id="EmailSMTP" name="EmailSMTP" value="'+SMTPSecure+'">';
		}
		else if(valor == 'Aol'){
			host = 'smtp.aol.com';
			SMTPSecure = 'tls';
			SMTPSecureRem = 'ssl';
			Porta = '587 ';
			EmailSMTP = '<input type="hidden" id="EmailSMTP" name="EmailSMTP" value="'+SMTPSecure+'">';
		}
		else{
			host = '';
			SMTPSecure = '';
			SMTPSecureRem = '';
			Porta = '';
			EmailSMTP = '';
		}
		
			if(valor == 'Personalizado'){
				$("#StatusEmailSMTP").html('');
				$("#EmailServidor").removeAttr('readonly');
				$("#EmailServidor").removeAttr('value');
				$("#EmailPorta").removeAttr('readonly');
				$("#EmailPorta").removeAttr('value');
				$("#EmailSMTP").removeAttr('disabled');
			}
			else{
				$("#EmailServidor").attr('value', host);
				$("#EmailSMTP").find('option[value="' + SMTPSecureRem + '"]').removeAttr('selected');
				$("#EmailSMTP").find('option[value="' + SMTPSecure + '"]').attr('selected','selected');
				$("#EmailSMTP").change();
				$("#EmailPorta").attr('value', Porta);
				
				$("#EmailServidor").attr('readonly', 'true');
				$("#EmailPorta").attr('readonly', 'true');
				$("#EmailSMTP").attr('disabled', 'true');
				$("#StatusEmailSMTP").html('');
				$("#StatusEmailSMTP").html(EmailSMTP);
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