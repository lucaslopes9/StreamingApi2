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
	
	$SQLUrlT = "SELECT * FROM backup";
	$SQLUrlT = $painel_geral->prepare($SQLUrlT);
	$SQLUrlT->execute();
	$LnUrlT = $SQLUrlT->fetch();
	
	$status = empty($LnUrlT['status']) ? "N" : $LnUrlT['status'];
	$tempo = empty($LnUrlT['tempo']) ? "" : $LnUrlT['tempo'];
	$horario = empty($LnUrlT['horario']) ? "" : $LnUrlT['horario'];
	$email = empty($LnUrlT['email']) ? "" : $LnUrlT['email'];
	
echo "<div class=\"modal animated fadeIn\" id=\"EditarAdmin\" tabindex=\"-1\" role=\"dialog\" aria-labelledby=\"smallModalHead\" aria-hidden=\"true\">
            <div class=\"modal-dialog\">
                <div class=\"modal-content\">
                    <div class=\"modal-header\">
                        <button type=\"button\" class=\"close\" data-dismiss=\"modal\"><span aria-hidden=\"true\">&times;</span><span class=\"sr-only\">".$_TRA['fechar']."</span></button>
                        <h4 class=\"modal-title\" id=\"smallModalHead\">".$_TRA['Backup']."</h4>
                    </div>
                    <div class=\"modal-body form-horizontal form-group-separated\">     
						<form id=\"validate\" role=\"form\" class=\"ConfigTeste form-horizontal\" action=\"javascript:MDouglasMS();\">
										
						 <div class=\"form-group\">
                        	<label class=\"col-md-3 control-label\">".$_TRA['Status']."</label>
                            	<div class=\"col-md-9\">                                        
                                	<select class=\"form-control select\" id=\"Status\" name=\"Status\">";
									
									if($status == "S"){
										echo "<option value=\"S\">".$_TRA['Ativado']."</option>
										<option value=\"N\">".$_TRA['Desativado']."</option>";
									}
									else{
										echo "<option value=\"N\">".$_TRA['Desativado']."</option>
										<option value=\"S\">".$_TRA['Ativado']."</option>";										
									}
									
									echo "</select>
                                 </div>
                        </div>
						
						 <div class=\"form-group\">
                        	<label class=\"col-md-3 control-label\">".$_TRA['Tempo']."</label>
                            	<div class=\"col-md-9\">                                        
                                	<select class=\"form-control select\" id=\"Tempo\" name=\"Tempo\">";
									
									if($tempo == 1){
										echo "
										<option value=\"1\">1 ".$_TRA['eeem']." 1 ".$_TRA['Hora']."</option>
										<option value=\"2\">2 ".$_TRA['eeem']." 2 ".$_TRA['Horas']."</option>
										<option value=\"3\">3 ".$_TRA['eeem']." 3 ".$_TRA['Horas']."</option>
										<option value=\"6\">6 ".$_TRA['eeem']." 6 ".$_TRA['Horas']."</option>
										<option value=\"12\">12 ".$_TRA['eeem']." 12 ".$_TRA['Horas']."</option>
										<option value=\"24\">1 ".$_TRA['dia']." ".$_TRA['eeem']." 1 ".$_TRA['dia']."</option>
										<option value=\"48\">2 ".$_TRA['dias']." ".$_TRA['eeem']." 2 ".$_TRA['dias']."</option>
										<option value=\"72\">3 ".$_TRA['dias']." ".$_TRA['eeem']." 3 ".$_TRA['dias']."</option>
										<option value=\"96\">4 ".$_TRA['dias']." ".$_TRA['eeem']." 4 ".$_TRA['dias']."</option>
										<option value=\"120\">5 ".$_TRA['dias']." ".$_TRA['eeem']." 5 ".$_TRA['dias']."</option>
										<option value=\"144\">6 ".$_TRA['dias']." ".$_TRA['eeem']." 6 ".$_TRA['dias']."</option>
										<option value=\"168\">7 ".$_TRA['dias']." ".$_TRA['eeem']." 7 ".$_TRA['dias']."</option>
										";
									}
									elseif($tempo == 2){
										echo "
										<option value=\"2\">2 ".$_TRA['eeem']." 2 ".$_TRA['Horas']."</option>
										<option value=\"3\">3 ".$_TRA['eeem']." 3 ".$_TRA['Horas']."</option>
										<option value=\"6\">6 ".$_TRA['eeem']." 6 ".$_TRA['Horas']."</option>
										<option value=\"12\">12 ".$_TRA['eeem']." 12 ".$_TRA['Horas']."</option>
										<option value=\"24\">1 ".$_TRA['dia']." ".$_TRA['eeem']." 1 ".$_TRA['dia']."</option>
										<option value=\"48\">2 ".$_TRA['dias']." ".$_TRA['eeem']." 2 ".$_TRA['dias']."</option>
										<option value=\"72\">3 ".$_TRA['dias']." ".$_TRA['eeem']." 3 ".$_TRA['dias']."</option>
										<option value=\"96\">4 ".$_TRA['dias']." ".$_TRA['eeem']." 4 ".$_TRA['dias']."</option>
										<option value=\"120\">5 ".$_TRA['dias']." ".$_TRA['eeem']." 5 ".$_TRA['dias']."</option>
										<option value=\"144\">6 ".$_TRA['dias']." ".$_TRA['eeem']." 6 ".$_TRA['dias']."</option>
										<option value=\"168\">7 ".$_TRA['dias']." ".$_TRA['eeem']." 7 ".$_TRA['dias']."</option>
										<option value=\"1\">1 ".$_TRA['eeem']." 1 ".$_TRA['Hora']."</option>
										";
									}
									elseif($tempo == 3){
										echo "
										<option value=\"3\">3 ".$_TRA['eeem']." 3 ".$_TRA['Horas']."</option>
										<option value=\"6\">6 ".$_TRA['eeem']." 6 ".$_TRA['Horas']."</option>
										<option value=\"12\">12 ".$_TRA['eeem']." 12 ".$_TRA['Horas']."</option>
										<option value=\"24\">1 ".$_TRA['dia']." ".$_TRA['eeem']." 1 ".$_TRA['dia']."</option>
										<option value=\"48\">2 ".$_TRA['dias']." ".$_TRA['eeem']." 2 ".$_TRA['dias']."</option>
										<option value=\"72\">3 ".$_TRA['dias']." ".$_TRA['eeem']." 3 ".$_TRA['dias']."</option>
										<option value=\"96\">4 ".$_TRA['dias']." ".$_TRA['eeem']." 4 ".$_TRA['dias']."</option>
										<option value=\"120\">5 ".$_TRA['dias']." ".$_TRA['eeem']." 5 ".$_TRA['dias']."</option>
										<option value=\"144\">6 ".$_TRA['dias']." ".$_TRA['eeem']." 6 ".$_TRA['dias']."</option>
										<option value=\"168\">7 ".$_TRA['dias']." ".$_TRA['eeem']." 7 ".$_TRA['dias']."</option>
										<option value=\"1\">1 ".$_TRA['eeem']." 1 ".$_TRA['Hora']."</option>
										<option value=\"2\">2 ".$_TRA['eeem']." 2 ".$_TRA['Horas']."</option>
										";
									}
									elseif($tempo == 6){
										echo "
										<option value=\"6\">6 ".$_TRA['eeem']." 6 ".$_TRA['Horas']."</option>
										<option value=\"12\">12 ".$_TRA['eeem']." 12 ".$_TRA['Horas']."</option>
										<option value=\"24\">1 ".$_TRA['dia']." ".$_TRA['eeem']." 1 ".$_TRA['dia']."</option>
										<option value=\"48\">2 ".$_TRA['dias']." ".$_TRA['eeem']." 2 ".$_TRA['dias']."</option>
										<option value=\"72\">3 ".$_TRA['dias']." ".$_TRA['eeem']." 3 ".$_TRA['dias']."</option>
										<option value=\"96\">4 ".$_TRA['dias']." ".$_TRA['eeem']." 4 ".$_TRA['dias']."</option>
										<option value=\"120\">5 ".$_TRA['dias']." ".$_TRA['eeem']." 5 ".$_TRA['dias']."</option>
										<option value=\"144\">6 ".$_TRA['dias']." ".$_TRA['eeem']." 6 ".$_TRA['dias']."</option>
										<option value=\"168\">7 ".$_TRA['dias']." ".$_TRA['eeem']." 7 ".$_TRA['dias']."</option>
										<option value=\"1\">1 ".$_TRA['eeem']." 1 ".$_TRA['Hora']."</option>
										<option value=\"2\">2 ".$_TRA['eeem']." 2 ".$_TRA['Horas']."</option>
										<option value=\"3\">3 ".$_TRA['eeem']." 3 ".$_TRA['Horas']."</option>
										";
									}
									elseif($tempo == 12){
										echo "
										<option value=\"12\">12 ".$_TRA['eeem']." 12 ".$_TRA['Horas']."</option>
										<option value=\"24\">1 ".$_TRA['dia']." ".$_TRA['eeem']." 1 ".$_TRA['dia']."</option>
										<option value=\"48\">2 ".$_TRA['dias']." ".$_TRA['eeem']." 2 ".$_TRA['dias']."</option>
										<option value=\"72\">3 ".$_TRA['dias']." ".$_TRA['eeem']." 3 ".$_TRA['dias']."</option>
										<option value=\"96\">4 ".$_TRA['dias']." ".$_TRA['eeem']." 4 ".$_TRA['dias']."</option>
										<option value=\"120\">5 ".$_TRA['dias']." ".$_TRA['eeem']." 5 ".$_TRA['dias']."</option>
										<option value=\"144\">6 ".$_TRA['dias']." ".$_TRA['eeem']." 6 ".$_TRA['dias']."</option>
										<option value=\"168\">7 ".$_TRA['dias']." ".$_TRA['eeem']." 7 ".$_TRA['dias']."</option>
										<option value=\"1\">1 ".$_TRA['eeem']." 1 ".$_TRA['Hora']."</option>
										<option value=\"2\">2 ".$_TRA['eeem']." 2 ".$_TRA['Horas']."</option>
										<option value=\"3\">3 ".$_TRA['eeem']." 3 ".$_TRA['Horas']."</option>
										<option value=\"6\">6 ".$_TRA['eeem']." 6 ".$_TRA['Horas']."</option>
										";
									}
									elseif($tempo == 24){
										echo "
										<option value=\"24\">1 ".$_TRA['dia']." ".$_TRA['eeem']." 1 ".$_TRA['dia']."</option>
										<option value=\"48\">2 ".$_TRA['dias']." ".$_TRA['eeem']." 2 ".$_TRA['dias']."</option>
										<option value=\"72\">3 ".$_TRA['dias']." ".$_TRA['eeem']." 3 ".$_TRA['dias']."</option>
										<option value=\"96\">4 ".$_TRA['dias']." ".$_TRA['eeem']." 4 ".$_TRA['dias']."</option>
										<option value=\"120\">5 ".$_TRA['dias']." ".$_TRA['eeem']." 5 ".$_TRA['dias']."</option>
										<option value=\"144\">6 ".$_TRA['dias']." ".$_TRA['eeem']." 6 ".$_TRA['dias']."</option>
										<option value=\"168\">7 ".$_TRA['dias']." ".$_TRA['eeem']." 7 ".$_TRA['dias']."</option>
										<option value=\"1\">1 ".$_TRA['eeem']." 1 ".$_TRA['Hora']."</option>
										<option value=\"2\">2 ".$_TRA['eeem']." 2 ".$_TRA['Horas']."</option>
										<option value=\"3\">3 ".$_TRA['eeem']." 3 ".$_TRA['Horas']."</option>
										<option value=\"6\">6 ".$_TRA['eeem']." 6 ".$_TRA['Horas']."</option>
										<option value=\"12\">12 ".$_TRA['eeem']." 12 ".$_TRA['Horas']."</option>
										";
									}
									elseif($tempo == 48){
										echo "
										<option value=\"48\">2 ".$_TRA['dias']." ".$_TRA['eeem']." 2 ".$_TRA['dias']."</option>
										<option value=\"72\">3 ".$_TRA['dias']." ".$_TRA['eeem']." 3 ".$_TRA['dias']."</option>
										<option value=\"96\">4 ".$_TRA['dias']." ".$_TRA['eeem']." 4 ".$_TRA['dias']."</option>
										<option value=\"120\">5 ".$_TRA['dias']." ".$_TRA['eeem']." 5 ".$_TRA['dias']."</option>
										<option value=\"144\">6 ".$_TRA['dias']." ".$_TRA['eeem']." 6 ".$_TRA['dias']."</option>
										<option value=\"168\">7 ".$_TRA['dias']." ".$_TRA['eeem']." 7 ".$_TRA['dias']."</option>
										<option value=\"1\">1 ".$_TRA['eeem']." 1 ".$_TRA['Hora']."</option>
										<option value=\"2\">2 ".$_TRA['eeem']." 2 ".$_TRA['Horas']."</option>
										<option value=\"3\">3 ".$_TRA['eeem']." 3 ".$_TRA['Horas']."</option>
										<option value=\"6\">6 ".$_TRA['eeem']." 6 ".$_TRA['Horas']."</option>
										<option value=\"12\">12 ".$_TRA['eeem']." 12 ".$_TRA['Horas']."</option>
										<option value=\"24\">1 ".$_TRA['dia']." ".$_TRA['eeem']." 1 ".$_TRA['dia']."</option>
										";
									}
									elseif($tempo == 72){
										echo "
										<option value=\"72\">3 ".$_TRA['dias']." ".$_TRA['eeem']." 3 ".$_TRA['dias']."</option>
										<option value=\"96\">4 ".$_TRA['dias']." ".$_TRA['eeem']." 4 ".$_TRA['dias']."</option>
										<option value=\"120\">5 ".$_TRA['dias']." ".$_TRA['eeem']." 5 ".$_TRA['dias']."</option>
										<option value=\"144\">6 ".$_TRA['dias']." ".$_TRA['eeem']." 6 ".$_TRA['dias']."</option>
										<option value=\"168\">7 ".$_TRA['dias']." ".$_TRA['eeem']." 7 ".$_TRA['dias']."</option>
										<option value=\"1\">1 ".$_TRA['eeem']." 1 ".$_TRA['Hora']."</option>
										<option value=\"2\">2 ".$_TRA['eeem']." 2 ".$_TRA['Horas']."</option>
										<option value=\"3\">3 ".$_TRA['eeem']." 3 ".$_TRA['Horas']."</option>
										<option value=\"6\">6 ".$_TRA['eeem']." 6 ".$_TRA['Horas']."</option>
										<option value=\"12\">12 ".$_TRA['eeem']." 12 ".$_TRA['Horas']."</option>
										<option value=\"24\">1 ".$_TRA['dia']." ".$_TRA['eeem']." 1 ".$_TRA['dia']."</option>
										<option value=\"48\">2 ".$_TRA['dias']." ".$_TRA['eeem']." 2 ".$_TRA['dias']."</option>
										";
									}
									elseif($tempo == 96){
										echo "
										<option value=\"96\">4 ".$_TRA['dias']." ".$_TRA['eeem']." 4 ".$_TRA['dias']."</option>
										<option value=\"120\">5 ".$_TRA['dias']." ".$_TRA['eeem']." 5 ".$_TRA['dias']."</option>
										<option value=\"144\">6 ".$_TRA['dias']." ".$_TRA['eeem']." 6 ".$_TRA['dias']."</option>
										<option value=\"168\">7 ".$_TRA['dias']." ".$_TRA['eeem']." 7 ".$_TRA['dias']."</option>
										<option value=\"1\">1 ".$_TRA['eeem']." 1 ".$_TRA['Hora']."</option>
										<option value=\"2\">2 ".$_TRA['eeem']." 2 ".$_TRA['Horas']."</option>
										<option value=\"3\">3 ".$_TRA['eeem']." 3 ".$_TRA['Horas']."</option>
										<option value=\"6\">6 ".$_TRA['eeem']." 6 ".$_TRA['Horas']."</option>
										<option value=\"12\">12 ".$_TRA['eeem']." 12 ".$_TRA['Horas']."</option>
										<option value=\"24\">1 ".$_TRA['dia']." ".$_TRA['eeem']." 1 ".$_TRA['dia']."</option>
										<option value=\"48\">2 ".$_TRA['dias']." ".$_TRA['eeem']." 2 ".$_TRA['dias']."</option>
										<option value=\"72\">3 ".$_TRA['dias']." ".$_TRA['eeem']." 3 ".$_TRA['dias']."</option>
										";
									}
									elseif($tempo == 120){
										echo "
										<option value=\"120\">5 ".$_TRA['dias']." ".$_TRA['eeem']." 5 ".$_TRA['dias']."</option>
										<option value=\"144\">6 ".$_TRA['dias']." ".$_TRA['eeem']." 6 ".$_TRA['dias']."</option>
										<option value=\"168\">7 ".$_TRA['dias']." ".$_TRA['eeem']." 7 ".$_TRA['dias']."</option>
										<option value=\"1\">1 ".$_TRA['eeem']." 1 ".$_TRA['Hora']."</option>
										<option value=\"2\">2 ".$_TRA['eeem']." 2 ".$_TRA['Horas']."</option>
										<option value=\"3\">3 ".$_TRA['eeem']." 3 ".$_TRA['Horas']."</option>
										<option value=\"6\">6 ".$_TRA['eeem']." 6 ".$_TRA['Horas']."</option>
										<option value=\"12\">12 ".$_TRA['eeem']." 12 ".$_TRA['Horas']."</option>
										<option value=\"24\">1 ".$_TRA['dia']." ".$_TRA['eeem']." 1 ".$_TRA['dia']."</option>
										<option value=\"48\">2 ".$_TRA['dias']." ".$_TRA['eeem']." 2 ".$_TRA['dias']."</option>
										<option value=\"72\">3 ".$_TRA['dias']." ".$_TRA['eeem']." 3 ".$_TRA['dias']."</option>
										<option value=\"96\">4 ".$_TRA['dias']." ".$_TRA['eeem']." 4 ".$_TRA['dias']."</option>
										";
									}
									elseif($tempo == 144){
										echo "
										<option value=\"144\">6 ".$_TRA['dias']." ".$_TRA['eeem']." 6 ".$_TRA['dias']."</option>
										<option value=\"168\">7 ".$_TRA['dias']." ".$_TRA['eeem']." 7 ".$_TRA['dias']."</option>
										<option value=\"1\">1 ".$_TRA['eeem']." 1 ".$_TRA['Hora']."</option>
										<option value=\"2\">2 ".$_TRA['eeem']." 2 ".$_TRA['Horas']."</option>
										<option value=\"3\">3 ".$_TRA['eeem']." 3 ".$_TRA['Horas']."</option>
										<option value=\"6\">6 ".$_TRA['eeem']." 6 ".$_TRA['Horas']."</option>
										<option value=\"12\">12 ".$_TRA['eeem']." 12 ".$_TRA['Horas']."</option>
										<option value=\"24\">1 ".$_TRA['dia']." ".$_TRA['eeem']." 1 ".$_TRA['dia']."</option>
										<option value=\"48\">2 ".$_TRA['dias']." ".$_TRA['eeem']." 2 ".$_TRA['dias']."</option>
										<option value=\"72\">3 ".$_TRA['dias']." ".$_TRA['eeem']." 3 ".$_TRA['dias']."</option>
										<option value=\"96\">4 ".$_TRA['dias']." ".$_TRA['eeem']." 4 ".$_TRA['dias']."</option>
										<option value=\"120\">5 ".$_TRA['dias']." ".$_TRA['eeem']." 5 ".$_TRA['dias']."</option>
										";
									}
									elseif($tempo == 168){
										echo "
										<option value=\"168\">7 ".$_TRA['dias']." ".$_TRA['eeem']." 7 ".$_TRA['dias']."</option>
										<option value=\"1\">1 ".$_TRA['eeem']." 1 ".$_TRA['Hora']."</option>
										<option value=\"2\">2 ".$_TRA['eeem']." 2 ".$_TRA['Horas']."</option>
										<option value=\"3\">3 ".$_TRA['eeem']." 3 ".$_TRA['Horas']."</option>
										<option value=\"6\">6 ".$_TRA['eeem']." 6 ".$_TRA['Horas']."</option>
										<option value=\"12\">12 ".$_TRA['eeem']." 12 ".$_TRA['Horas']."</option>
										<option value=\"24\">1 ".$_TRA['dia']." ".$_TRA['eeem']." 1 ".$_TRA['dia']."</option>
										<option value=\"48\">2 ".$_TRA['dias']." ".$_TRA['eeem']." 2 ".$_TRA['dias']."</option>
										<option value=\"72\">3 ".$_TRA['dias']." ".$_TRA['eeem']." 3 ".$_TRA['dias']."</option>
										<option value=\"96\">4 ".$_TRA['dias']." ".$_TRA['eeem']." 4 ".$_TRA['dias']."</option>
										<option value=\"120\">5 ".$_TRA['dias']." ".$_TRA['eeem']." 5 ".$_TRA['dias']."</option>
										<option value=\"144\">6 ".$_TRA['dias']." ".$_TRA['eeem']." 6 ".$_TRA['dias']."</option>
										";
									}
									else{
										echo "
										<option value=\"1\">1 ".$_TRA['eeem']." 1 ".$_TRA['Hora']."</option>
										<option value=\"2\">2 ".$_TRA['eeem']." 2 ".$_TRA['Horas']."</option>
										<option value=\"3\">3 ".$_TRA['eeem']." 3 ".$_TRA['Horas']."</option>
										<option value=\"6\">6 ".$_TRA['eeem']." 6 ".$_TRA['Horas']."</option>
										<option value=\"12\">12 ".$_TRA['eeem']." 12 ".$_TRA['Horas']."</option>
										<option value=\"24\">1 ".$_TRA['dia']." ".$_TRA['eeem']." 1 ".$_TRA['dia']."</option>
										<option value=\"48\">2 ".$_TRA['dias']." ".$_TRA['eeem']." 2 ".$_TRA['dias']."</option>
										<option value=\"72\">3 ".$_TRA['dias']." ".$_TRA['eeem']." 3 ".$_TRA['dias']."</option>
										<option value=\"96\">4 ".$_TRA['dias']." ".$_TRA['eeem']." 4 ".$_TRA['dias']."</option>
										<option value=\"120\">5 ".$_TRA['dias']." ".$_TRA['eeem']." 5 ".$_TRA['dias']."</option>
										<option value=\"144\">6 ".$_TRA['dias']." ".$_TRA['eeem']." 6 ".$_TRA['dias']."</option>
										<option value=\"168\">7 ".$_TRA['dias']." ".$_TRA['eeem']." 7 ".$_TRA['dias']."</option>
										";
									}
									
									echo "</select>
                                 </div>
                        </div>
						
						<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['email']."</label>
                            <div class=\"col-md-9\">
                                <input id=\"Email\" name=\"Email\" type=\"text\" class=\"validate[required] form-control\" value=\"".$email."\">
                            </div>
                        </div>
						
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
		
		panel_refresh($(".ConfigTeste"));
				
		$.post('EnviarConfigBackup.php', Data, function(resposta) {
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