<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;

$ColunaAcesso = array('PerfilEditar');
$VerificarAcesso = VerificarAcesso('perfil', $ColunaAcesso);
$PerfilEditar = $VerificarAcesso[0];

if($PerfilEditar == 'S'){
	
if ($_SERVER['REQUEST_METHOD'] == 'POST') {

$id = (isset($_POST['id'])) ? $_POST['id'] : '';

if( !empty($id) ){

$SQLCSP = "SELECT id, painel, imagem, nome, valorcsp, url, porta, tipo, bloqueado FROM perfil WHERE id = :id";
$SQLCSP = $painel_geral->prepare($SQLCSP);
$SQLCSP->bindParam(':id', $id, PDO::PARAM_INT);
$SQLCSP->execute();
$LnCSP = $SQLCSP->fetch();

$SQLPainel = "SELECT nome FROM painel WHERE id = :id";
$SQLPainel = $painel_geral->prepare($SQLPainel);
$SQLPainel->bindParam(':id', $LnCSP['painel'], PDO::PARAM_INT);
$SQLPainel->execute();
$TotalPainel = count($SQLPainel->fetchAll());

$SQLPainel2 = "SELECT id, nome FROM painel WHERE id != :id";
$SQLPainel2 = $painel_geral->prepare($SQLPainel2);
$SQLPainel2->bindParam(':id', $LnCSP['painel'], PDO::PARAM_INT);
$SQLPainel2->execute();
$TotalPainel2 = count($SQLPainel2->fetchAll());

$SQLImagem = "SELECT id, nome, img FROM perfil_icone WHERE id != :id";
$SQLImagem = $painel_geral->prepare($SQLImagem);
$SQLImagem->bindParam(':id', $LnCSP['imagem'], PDO::PARAM_INT);
$SQLImagem->execute();
$TotalImagem = count($SQLImagem->fetchAll());

$SQLImagem2 = "SELECT nome, img FROM perfil_icone WHERE id = :id";
$SQLImagem2 = $painel_geral->prepare($SQLImagem2);
$SQLImagem2->bindParam(':id', $LnCSP['imagem'], PDO::PARAM_INT);
$SQLImagem2->execute();
$TotamImagem2 = count($SQLImagem2->fetchAll());

echo "<div class=\"modal animated fadeIn\" id=\"EditarModal\" tabindex=\"-1\" role=\"dialog\" aria-labelledby=\"smallModalHead\" aria-hidden=\"true\">
            <div class=\"modal-dialog\">
                <div class=\"modal-content\">
                    <div class=\"modal-header\">
                        <button type=\"button\" class=\"close\" data-dismiss=\"modal\"><span aria-hidden=\"true\">&times;</span><span class=\"sr-only\">".$_TRA['fechar']."</span></button>
                        <h4 class=\"modal-title\" id=\"smallModalHead\">".$LnCSP['nome']."</h4>
                    </div>
                    <div class=\"modal-body form-horizontal form-group-separated\">     
						<form id=\"validate\" role=\"form\" class=\"EditarPerfilCSP form-horizontal\" action=\"javascript:MDouglasMS();\">
                        
						<div class=\"form-group\">
                        	<label class=\"col-md-3 control-label\">".$_TRA['SCSP']."</label>
                            	<div class=\"col-md-9\">                                        
                                	<select class=\"form-control select\" id=\"EditarCSP\" name=\"EditarCSP\">";
										
									if( ($TotalPainel > 0) || ($TotalPainel2 > 0)){
										if($TotalPainel > 0){
										$SQLPainel->execute();
										$LnPainel = $SQLPainel->fetch();
                                    	echo "<option value=\"".$LnCSP['painel']."\">".$LnPainel['nome']."</option>";
										}
										
										if($TotalPainel2 > 0){
										$SQLPainel2->execute();
										while($LnPainel2 = $SQLPainel2->fetch()){
											echo "<option value=\"".$LnPainel2['id']."\">".$LnPainel2['nome']."</option>";
										}
										}
									}
									else{
										echo "<option value=\"0\">".$_TRA['SSCSP']."</option>";
									}
										
										echo "
                                     </select>
                                 </div>
                        </div>
						
						<div class=\"form-group\">
                        	<label class=\"col-md-3 control-label\">".$_TRA['Tipo']."</label>
                            	<div class=\"col-md-9\">                                        
                                	<select class=\"form-control select\" id=\"EditarTipo\" name=\"EditarTipo\">";
									
									if($LnCSP['tipo'] == "SAT"){
                                    	echo "<option value=\"SAT\">".$_TRA['satelite']."</option>
										<option value=\"CAB\">".$_TRA['cabo']."</option>";
									}
									else{
										echo "<option value=\"CAB\">".$_TRA['cabo']."</option>
										<option value=\"SAT\">".$_TRA['satelite']."</option>
										";
									}
                                   echo " </select>
                                </div>
                        </div>
						
                        <div class=\"form-group\">
                        	<label class=\"col-md-3 control-label\">".$_TRA['Imagem']."</label>
                            	<div class=\"col-md-9\">                                        
                                	<select class=\"form-control select\" id=\"EditarImagem\" name=\"EditarImagem\">";
										
									if( ($TotamImagem2 > 0) || ($TotalImagem > 0)){
										if($TotamImagem2 > 0){
										$SQLImagem2->execute();
										$LnImagem2 = $SQLImagem2->fetch();
										$FotoPerfil2 = FotoPerfil($LnImagem2['img']);
										echo "<option data-content='<img src=\"".$FotoPerfil2."\" height=\"16\" width=\"16\"><span style=\"padding:0px 0px 0px 10px;\">".ucfirst($LnImagem2['nome'])."</span>' value=\"".$LnCSP['imagem']."\"></option>";
										}
										
										if($TotalImagem > 0){
										$SQLImagem->execute();
										while($LnImagem = $SQLImagem->fetch()){
										$FotoPerfil = FotoPerfil($LnImagem['img']);
										echo "<option data-content='<img src=\"".$FotoPerfil."\" height=\"16\" width=\"16\"><span style=\"padding:0px 0px 0px 10px;\">".ucfirst($LnImagem['nome'])."</span>' value=\"".$LnImagem['id']."\"></option>";
										}
										}
									}
									else{
										echo "<option value=\"0\">".$_TRA['SImagem']."</option>";
									}
										
										echo "
                                     </select>
                                 </div>
                        </div>
						
                        <div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['nome']."</label>
                            <div class=\"col-md-9\">
                                <input id=\"EditarNome\" name=\"EditarNome\" type=\"text\" class=\"validate[required] form-control\" value=\"".$LnCSP['nome']."\">
                            </div>
                        </div>
						<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['valorcsp']."</label>
                            <div class=\"col-md-9\">
                                <input id=\"EditarValorCSP\" name=\"EditarValorCSP\" type=\"text\" class=\"validate[required] form-control\" value=\"".ValorPerfil($LnCSP['valorcsp'])."\">
                            </div>
                        </div>
						<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['Url']."</label>
                            <div class=\"col-md-9\">
                                <input id=\"EditarUrl\" name=\"EditarUrl\" type=\"text\" class=\"validate[required] form-control\" value=\"".$LnCSP['url']."\">
                            </div>
                        </div>
						
						<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['Porta']."</label>
                            <div class=\"col-md-9\">
                                <input id=\"EditarPorta\" name=\"EditarPorta\" type=\"text\" class=\"validate[required,custom[integer],custom[number]] form-control\" value=\"".$LnCSP['porta']."\">
                            </div>
                        </div>
						
						<input type=\"hidden\" name=\"EditarID\" id=\"EditarID\" value=\"".$id."\">
						
						</form>
                    </div>
                    <div class=\"modal-footer\">
						<div id=\"StatusModal\"></div>
                        <button type=\"button\" class=\"SalvarEditar btn btn-danger\">".$_TRA['alterar']."</button>
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

<!-- START TEMPLATE -->    
<?php include_once("js/settings".Idioma(2).".php"); ?>
<script type="text/javascript" src="js/plugins.js"></script>         
<!-- END TEMPLATE -->

<script>
$("#EditarModal").modal("show");

$(function(){  
 $("button.SalvarEditar").click(function() { 
 
 		var Data = $(".EditarPerfilCSP").serialize();
		
		$('#StatusModal').html("<center><img src=\"img/owl/AjaxLoader.gif\"><br><br></center>");
		
		$.post('EnviarEditarPerfilCSP.php', Data, function(resposta) {
				$("#StatusModal").html('');
				$("#StatusGeral").append(resposta);
		});
	});
});
</script>
   
<?php  
}
}

}else{
	echo Redirecionar('index.php');
}
}else{
	echo Redirecionar('login.php');
}	
?>