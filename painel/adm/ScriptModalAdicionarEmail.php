<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;
	
$ColunaAcesso = array('EmailadicionarAdicionar');
$VerificarAcesso = VerificarAcesso('email_adicionar', $ColunaAcesso);
$EmailadicionarAdicionar = $VerificarAcesso[0];
 
if($EmailadicionarAdicionar == 'S'){
	
echo "<div class=\"modal animated fadeIn\" id=\"EditarModal\" tabindex=\"-1\" role=\"dialog\" aria-labelledby=\"smallModalHead\" aria-hidden=\"true\">
            <div class=\"modal-dialog\">
                <div class=\"modal-content\">
                    <div class=\"modal-header\">
                        <button type=\"button\" class=\"close\" data-dismiss=\"modal\"><span aria-hidden=\"true\">&times;</span><span class=\"sr-only\">".$_TRA['fechar']."</span></button>
                        <h4 class=\"modal-title\" id=\"smallModalHead\">".$_TRA['Adicionar']."</h4>
                    </div>
                    <div class=\"modal-body form-horizontal form-group-separated\">     
						<form id=\"validate\" role=\"form\" class=\"AdicionarEmail form-horizontal\" action=\"javascript:MDouglasMS();\">
						
						<div class=\"form-group\">
                        	<label class=\"col-md-3 control-label\">".$_TRA['Servidor']."</label>
                            	<div class=\"col-md-9\">                                        
                                	<select class=\"form-control select\" id=\"EmailPersonalizado\" name=\"EmailPersonalizado\">
                                    	<option value=\"Personalizado\">Personalizado</option>
										<option value=\"Gmail\">Gmail</option>
										<option value=\"Hotmail\">Hotmail</option>
										<option value=\"Yahoo\">Yahoo</option>
										<option value=\"Bol\">Bol</option>
										<option value=\"Aol\">Aol</option>
                                     </select>
                                 </div>
                        </div>
						
                        <div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['Exibicao']."</label>
                            <div class=\"col-md-9\">
                                <input id=\"EmailExibicao\" name=\"EmailExibicao\" type=\"text\" class=\"validate[required] form-control\">
                            </div>
                        </div>
                        <div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['email']."</label>
                            <div class=\"col-md-9\">
                                <input id=\"EmailEmail\" name=\"EmailEmail\" type=\"text\" class=\"validate[required,custom[email]] form-control\">
                            </div>
                        </div>
						
						<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['Usuario']."</label>
                            <div class=\"col-md-9\">
                                <input id=\"EmailUsuario\" name=\"EmailUsuario\" type=\"text\" class=\"validate[required] form-control\">
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
                                	<select class=\"form-control select\" id=\"EmailSMTP\" name=\"EmailSMTP\">
                                    	<option value=\"ssl\">SSL</option>
										<option value=\"tls\">TLS</option>
                                     </select>
									 <span id=\"StatusEmailSMTP\"></span>
                                 </div>
                        </div>
						
						<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['ServidorSMTP']."</label>
                            <div class=\"col-md-9\">
                                <input id=\"EmailServidor\" name=\"EmailServidor\" type=\"text\" class=\"validate[required] form-control\">
                            </div>
                        </div>
						
						<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['Porta']."</label>
                            <div class=\"col-md-9\">
                                <input id=\"EmailPorta\" name=\"EmailPorta\" type=\"text\" class=\"validate[required,custom[integer],custom[number]] form-control\">
                            </div>
                        </div>
						
						
						
						
						</form>
                    </div>
                    <div class=\"modal-footer\">
						<div id=\"StatusModal\"></div>
						<button type=\"button\" class=\"btn btn-default\" data-dismiss=\"modal\">".$_TRA['fechar']."</button>
                        <button type=\"button\" class=\"SalvarEmail btn btn-danger\">".$_TRA['Adicionar']."</button>
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
 $("button.SalvarEmail").click(function() { 
 
		 var Data = $(".AdicionarEmail").serialize();
		
		$('#StatusModal').html("<center><img src=\"img/owl/AjaxLoader.gif\"><br><br></center>");
		
		$.post('EnviarAdicionarEmail.php', Data, function(resposta) {
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