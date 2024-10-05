<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;
	
	$UserOnline = InfoUser(2);
	$SQLUrlT = "SELECT status, tempo, cemail, email FROM urlteste WHERE CadUser = :CadUser";
	$SQLUrlT = $painel_geral->prepare($SQLUrlT);
	$SQLUrlT->bindParam(':CadUser', $UserOnline, PDO::PARAM_STR);
	$SQLUrlT->execute();
	$LnUrlT = $SQLUrlT->fetch();
	
	$status = empty($LnUrlT['status']) ? "N" : $LnUrlT['status'];
	$tempo = empty($LnUrlT['tempo']) ? "" : $LnUrlT['tempo'];
	$cemail = empty($LnUrlT['cemail']) ? "N" : $LnUrlT['cemail'];
	$email = empty($LnUrlT['email']) ? "" : $LnUrlT['email'];
	
echo "<div class=\"modal animated fadeIn\" id=\"EditarAdmin\" tabindex=\"-1\" role=\"dialog\" aria-labelledby=\"smallModalHead\" aria-hidden=\"true\">
            <div class=\"modal-dialog\">
                <div class=\"modal-content\">
                    <div class=\"modal-header\">
                        <button type=\"button\" class=\"close\" data-dismiss=\"modal\"><span aria-hidden=\"true\">&times;</span><span class=\"sr-only\">".$_TRA['fechar']."</span></button>
                        <h4 class=\"modal-title\" id=\"smallModalHead\">".$_TRA['udt']."</h4>
                    </div>
                    <div class=\"modal-body form-horizontal form-group-separated\">     
						<form id=\"validate\" role=\"form\" class=\"ConfigTeste form-horizontal\" action=\"javascript:MDouglasMS();\">
										
						 <div class=\"form-group\">
                        	<label class=\"col-md-3 control-label\">".$_TRA['Status']."</label>
                            	<div class=\"col-md-9\">                                        
                                	<select class=\"form-control select\" id=\"EditarStatus\" name=\"EditarStatus\">";
									
									if($status == "S"){
										echo "<option value=\"S\">".$_TRA['disponivel']."</option>
										<option value=\"N\">".$_TRA['indisponivel']."</option>";
									}
									else{
										echo "<option value=\"N\">".$_TRA['indisponivel']."</option>
										<option value=\"S\">".$_TRA['disponivel']."</option>";										
									}
									
									echo "</select>
                                 </div>
                        </div>
						
						<div class=\"form-group\">
                        	<label class=\"col-md-3 control-label\">".$_TRA['Tempo']."</label>
                            	<div class=\"col-md-9\">                                        
                                	<select class=\"form-control select\" id=\"EditarTempo\" name=\"EditarTempo\">";
								
									echo VerificarTempoTesteEditar($tempo);
									
                                    echo "</select>
                                 </div>
                        </div>
						
                        <div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['copiade']."</label>
                           <div class=\"col-md-9\">                                        
                                	<select class=\"form-control select\" id=\"EditarCopia\" name=\"EditarCopia\">";
									
									if($cemail == "S"){
										echo "<option value=\"S\">".$_TRA['sim']."</option>
										<option value=\"N\">".$_TRA['nao']."</option>";
									}
									else{
										echo "<option value=\"N\">".$_TRA['nao']."</option>
										<option value=\"S\">".$_TRA['sim']."</option>";
									}
									
                                    echo "</select>
                            </div>
                        </div>
						
                        <div class=\"form-group\" id=\"StatusConfigTeste\">";
						if($cemail == "S"){
							echo "
							<div class=\"form-group\">
    							<label class=\"col-md-3 control-label\">".$_TRA['email']."</label>
        						<div class=\"col-md-9\">
           							<input id=\"EditarEmail\" name=\"EditarEmail\" value=\"".$email."\" type=\"text\" class=\"validate[custom[email]] form-control\">
           						</div>
   							</div>
							";							
						}
						echo "</div>
						
						</form>
                    </div>
                    <div class=\"modal-footer\">
						<div id=\"StatusModal\"></div>
                        <button type=\"button\" class=\"SalvarConfigTeste btn btn-danger\">".$_TRA['configurar']."</button>
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

<!-- START TEMPLATE -->  
<?php include_once("js/settings".Idioma(2).".php"); ?>   
<script type="text/javascript" src="js/plugins.js"></script>     
<!-- END TEMPLATE -->      


<script>
$("#EditarAdmin").modal("show");

$(function(){  
 $("button.SalvarConfigTeste").click(function() { 
 
 		var Data = $(".ConfigTeste").serialize();
		
		$('#StatusModal').html("<center><img src=\"img/owl/AjaxLoader.gif\"><br><br></center>");
		
		$.post('EnviarConfigTeste.php', Data, function(resposta) {
				$("#StatusModal").html('');
				$("#StatusGeral").append(resposta);
		});
	});
});

$(function(){
	$(".ConfigTeste select[name=EditarCopia]").change(function(){
		
		var id = $(this).val();
		
		$.post('ExibirSelectConfigTeste.php', {id: id}, function(resposta) {
				$("#StatusConfigTeste").html('');
				$("#StatusConfigTeste").html(resposta);
		});
	});
});
</script>

<?php  
}else{
	echo Redirecionar('login.php');
}	
?>