<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;
	
$ColunaAcesso = array('OpcoesCircular');
$VerificarAcesso = VerificarAcesso('opcoes', $ColunaAcesso);
$OpcoesCircular = $VerificarAcesso[0];
 
if($OpcoesCircular == 'S'){
	
$CadUser = InfoUser(2);
			
echo "<div class=\"modal animated fadeIn\" id=\"EditarModalCircular\" tabindex=\"-1\" role=\"dialog\" aria-labelledby=\"smallModalHead\" aria-hidden=\"true\">
            <div class=\"modal-dialog\">
                <div class=\"modal-content\">
                    <div class=\"modal-header\">
                        <button type=\"button\" class=\"close\" data-dismiss=\"modal\"><span aria-hidden=\"true\">&times;</span><span class=\"sr-only\">".$_TRA['fechar']."</span></button>
                        <h4 class=\"modal-title\" id=\"smallModalHead\">".$_TRA['ec']."</h4>
                    </div>
                    <div class=\"modal-body form-horizontal form-group-separated\">     
						<form id=\"validate\" role=\"form\" class=\"FormEnviarCircular form-horizontal\" action=\"javascript:MDouglasMS();\">
						
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
                            <label class=\"col-md-3 control-label\">".$_TRA['Assunto']."</label>
                            <div class=\"col-md-9\">
                                <input id=\"Assunto\" name=\"Assunto\" type=\"text\" class=\"validate[required] form-control\">
                            </div>
                        </div>
						
						
						<div class=\"form-group\">
                        	<label class=\"col-md-3 control-label\">".$_TRA['EmailModelo']."</label>
                            <div class=\"col-md-9\">                                        
                            <select class=\"form-control select\" id=\"Modelo\" name=\"Modelo\">
							".ModeloCircular()."
							</select>
                            </div>
                        </div>
						
						<div class=\"form-group\">
                        	<label class=\"col-md-3 control-label\">".$_TRA['EnviarPara']."</label>
                            	<div class=\"col-md-9\">                                        
                                	<select class=\"form-control select\" id=\"EnviarPara\" name=\"EnviarPara\">
                                    	".SelecionarArvoreAll($CadUser)."
                                     </select>
                                 </div>
                        </div>
						
						<div class=\"form-group\">
                        	<label class=\"col-md-3 control-label\">".$_TRA['rev']."</label>
                            	<div class=\"col-md-9\">                                        
                                	<select class=\"form-control select\" id=\"Revendedor\" name=\"Revendedor\">
                                    	<option value=\"N\">".$_TRA['nao']."</option>
										<option value=\"S\">".$_TRA['sim']."</option>
                                     </select>
                                 </div>
                        </div>
						
						<div class=\"form-group\">
                        	<label class=\"col-md-3 control-label\">".$_TRA['EntreDatas']."</label>
                            	<div class=\"col-md-9\">                                        
                                	<select class=\"form-control select\" id=\"EntreDatas\" name=\"EntreDatas\">
                                    	<option value=\"N\">".$_TRA['nao']."</option>
										<option value=\"S\">".$_TRA['sim']."</option>
                                     </select>
                                 </div>
                        </div>
						
						<span id=\"StatusEntreDatas\"></span>
						
						<div class=\"form-group\">
                        	<label class=\"col-md-3 control-label\">".$_TRA['grupo']."</label>
                            	<div class=\"col-md-9\">                                        
                                	<select class=\"form-control select\" id=\"Grupo\" name=\"Grupo\">
                                    	<option value=\"Todos\">".$_TRA['Todos']."</option>
										<option value=\"rev\">".$_TRA['rev']."</option>
										<option value=\"Usuario\">".$_TRA['Usuario']."</option>
										<option value=\"Teste\">".$_TRA['teste']."</option>
                                     </select>
                                 </div>
                        </div>
						
						<div class=\"form-group\">
                        	<label class=\"col-md-3 control-label\">".$_TRA['Status']."</label>
                            	<div class=\"col-md-9\">                                        
                                	<select class=\"form-control select\" id=\"Status\" name=\"Status\">
                                    	<option value=\"Todos\">".$_TRA['Todos']."</option>
										<option value=\"Ativos\">".$_TRA['Ativos']."</option>
										<option value=\"Esgotados\">".$_TRA['Esgotados']."</option>
										<option value=\"Bloqueados\">".$_TRA['Bloqueados']."</option>
                                     </select>
                                 </div>
                        </div>
						
						<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['Mensagem']."</label>
                            <div class=\"col-md-9\">
							    <textarea class=\"summernote\" id=\"Mensagem\" name=\"Mensagem\"></textarea>
                            </div>
                        </div>
												
						</form>
                    </div>
                    <div class=\"modal-footer\">
						<div id=\"StatusModal\"></div>
						<button type=\"button\" class=\"btn btn-default\" data-dismiss=\"modal\">".$_TRA['fechar']."</button>
                        <button type=\"button\" class=\"BotaoEnviarCircular btn btn-success\">".$_TRA['Enviar']."</button>
                    </div>
                </div>
            </div>
        </div>";
?>

<script type='text/javascript' src='js/plugins/validationengine/languages/jquery.validationEngine<?php echo Idioma(2); ?>.js'></script>
<script type='text/javascript' src='js/plugins/validationengine/jquery.validationEngine.js'></script>
<script type="text/javascript" src="js/plugins/bootstrap/bootstrap-select.js"></script>

<script type="text/javascript" src="js/plugins/summernote/summernote<?php echo Idioma(2); ?>.js"></script>

<script type='text/javascript' src='js/plugins.js'></script>

<script>
$("#EditarModalCircular").modal("show");

$(function(){  
 $("button.BotaoEnviarCircular").click(function() { 
 		
		var Assunto = $('.FormEnviarCircular input[name="Assunto"]').val();
		var EnviarPara = $('.FormEnviarCircular select[name="EnviarPara"]').val();
		var Revendedor = $('.FormEnviarCircular select[name="Revendedor"]').val();
		var EntreDatas = $('.FormEnviarCircular select[name="EntreDatas"]').val();
		var DataInicio = $('.FormEnviarCircular input[name="DataInicio"]').val();
		var DataFinal = $('.FormEnviarCircular input[name="DataFinal"]').val();
		var Grupo = $('.FormEnviarCircular select[name="Grupo"]').val();
		var Status = $('.FormEnviarCircular select[name="Status"]').val();
		var Mensagem = $('.FormEnviarCircular textarea[name="Mensagem"]').code();
	 	var EnviarCOM = $('.EnviarMsg select[name="EnviarCOM"]').val();
		 		
		panel_refresh($(".FormEnviarCircular"));
		
		$.post('EnviarMensagemCircular.php', {Assunto: Assunto, EnviarPara: EnviarPara, Revendedor: Revendedor, EntreDatas: EntreDatas, DataInicio: DataInicio, DataFinal: DataFinal, Grupo: Grupo, Status: Status, Mensagem: Mensagem, EnviarCOM: EnviarCOM}, function(resposta) {
			
				setTimeout(panel_refresh($(".FormEnviarCircular")),500);
			
				$("#StatusModal").html('');
				$("#StatusGeral").append(resposta);
		});
	});
});

$(function(){
	$(".FormEnviarCircular select[name=Modelo]").change(function(){
		
		var id = $(this).val();
		
		panel_refresh($(".FormEnviarCircular"));
				
		$.post('ExibirModeloCircular.php', {id: id}, function(resposta) {
			
				setTimeout(panel_refresh($(".FormEnviarCircular")),500);
				
				$("#Mensagem").code(resposta.trim());
				
		});
	});
});


$(function(){
	$(".FormEnviarCircular select[name=EntreDatas]").change(function(){
		
		var id = $(this).val();
		panel_refresh($(".FormEnviarCircular"));
		
		$.post('ExibirModeloEntreData.php', {id: id}, function(resposta) {
			
				setTimeout(panel_refresh($(".FormEnviarCircular")),500);
				$("#StatusEntreDatas").html(resposta.trim());
				
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