<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;
	
$ColunaAdmin = array('AdminAcesso');
$VerificarAcesso = VerificarAcesso('admin', $ColunaAdmin);
$AdminAcesso = $VerificarAcesso[0];
 
$ColunaRev = array('RevAcesso');
$VerificarAcesso = VerificarAcesso('rev', $ColunaRev);
$RevAcesso = $VerificarAcesso[0];

$ColunaAcesso = array('OpcoesGrupoAcesso');
$VerificarAcesso = VerificarAcesso('opcoes', $ColunaAcesso);
$OpcoesGrupoAcesso = $VerificarAcesso[0];
 
if( ($AdminAcesso == 'S') || ($RevAcesso == 'S') || ($OpcoesGrupoAcesso == 'S') ){

$CadUser = InfoUser(2);
$usuario = (isset($_POST['usuario'])) ? $_POST['usuario'] : $CadUser;
$id = (isset($_POST['id'])) ? $_POST['id'] : NULL;
$grupo = (isset($_POST['grupo'])) ? $_POST['grupo'] : 'N';
$lista = (isset($_POST['lista'])) ? $_POST['lista'] : 'N';
$UserList = (isset($_POST['UserList'])) ? $_POST['UserList'] : '';

if($lista == "N"){
echo "<div class=\"modal animated fadeIn\" id=\"EditarModal\" tabindex=\"-1\" role=\"dialog\" aria-labelledby=\"smallModalHead\" aria-hidden=\"true\">
            <div class=\"modal-dialog\">
                <div class=\"modal-content\">
                    <div class=\"modal-header\">
                        <button type=\"button\" class=\"close\" data-dismiss=\"modal\"><span aria-hidden=\"true\">&times;</span><span class=\"sr-only\">".$_TRA['fechar']."</span></button>
                        <h4 class=\"modal-title\" id=\"smallModalHead\">".$_TRA['Acesso']." (".$usuario.")</h4>
                    </div>
                    <div class=\"modal-body form-horizontal form-group-separated\">     
						<form id=\"validate\" role=\"form\" class=\"FormAcessos form-horizontal\" action=\"javascript:MDouglasMS();\">";
}
						
						if($grupo == "N"){
						
						$bloqueado = "N";
						$SQL = "SELECT id, nome FROM grupodeacesso WHERE CadUser = :CadUser AND bloqueado = :bloqueado ORDER by nome ASC";
						$SQL = $painel_geral->prepare($SQL);
						$SQL->bindParam(':CadUser', $CadUser, PDO::PARAM_STR);
						$SQL->bindParam(':bloqueado', $bloqueado, PDO::PARAM_STR);
						$SQL->execute();
						$TotalGrupo = count($SQL->fetchAll());
						
						echo "
						<div class=\"form-group\">
                        	<label class=\"col-md-3 control-label\">".$_TRA['gda']."</label>
                            	<div class=\"col-md-9\">                                        
                                	<select class=\"form-control select\" id=\"EditarGrupo\" name=\"EditarGrupo\">";
									
									if($TotalGrupo > 0){
										echo "<option>".$_TRA['sugda']."</option>";
									$SQL->execute();
									while($Ln = $SQL->fetch()){
										echo "<option value=\"".$Ln['id']."\">".$Ln['nome']."</option>";
									}
									}
									else{
										echo "<option>".$_TRA['negda']."</option>";
									}
                                    
									echo "</select>
                                 </div>
                        </div>
						";
						}
						
						echo "<span id=\"StatusLista\">";
						
						//Noticias
						$SelecionarAcessos = SelecionarAcessos('noticias', $usuario, $grupo, $id);
						$ArrayAdd = array();
						$ArrayAdd[] = array('NoticiaVisualizar', $_TRA['Visualizar'], 'S');
						$ArrayAdd[] = array('NoticiaEditar', $_TRA['editar'], $SelecionarAcessos['NoticiaEditar']);
						$ArrayAdd[] = array('NoticiaExcluir', $_TRA['excluir'], $SelecionarAcessos['NoticiaExcluir']);
						$ArrayAdd[] = array('NoticiaAdicionar', $_TRA['Adicionar'], $SelecionarAcessos['NoticiaAdicionar']);
						$Inserir = InserirCheckbox($ArrayAdd, 'noticias');
						
						if(!empty($Inserir)){						
						echo "<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">Noticias</label>
                            <div class=\"col-md-9\">
							".$Inserir."
                            </div>
                        </div>";
						}
					
						//Administrador
						$SelecionarAcessos = SelecionarAcessos('admin', $usuario, $grupo, $id);
						$ArrayAdd = array();
						$ArrayAdd[] = array('AdminVisualizar', $_TRA['Visualizar'], $SelecionarAcessos['AdminVisualizar']);
						$ArrayAdd[] = array('AdminAcesso', $_TRA['Acesso'], $SelecionarAcessos['AdminAcesso']);
						$ArrayAdd[] = array('AdminInfo', $_TRA['info'], $SelecionarAcessos['AdminInfo']);
						$ArrayAdd[] = array('AdminMensagem', $_TRA['Mensagem'], $SelecionarAcessos['AdminMensagem']);
						$ArrayAdd[] = array('AdminBloquear', $_TRA['bloquear'], $SelecionarAcessos['AdminBloquear']);
						$ArrayAdd[] = array('AdminDesativar', $_TRA['desativar'], $SelecionarAcessos['AdminDesativar']);
						$ArrayAdd[] = array('AdminEditar', $_TRA['editar'], $SelecionarAcessos['AdminEditar']);
						$ArrayAdd[] = array('AdminExcluir', $_TRA['excluir'], $SelecionarAcessos['AdminExcluir']);
						$ArrayAdd[] = array('AdminAdicionar', $_TRA['Adicionar'], $SelecionarAcessos['AdminAdicionar']);
						$ArrayAdd[] = array('AdminLogin', $_TRA['au'], $SelecionarAcessos['AdminLogin']);
						$Inserir = InserirCheckbox($ArrayAdd, 'admin');
																	
						if(!empty($Inserir)){						
						echo "<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['admin']."</label>
                            <div class=\"col-md-9\">
							".$Inserir."
                            </div>
                        </div>";
						}
						
						//Revendedor
						$SelecionarAcessos = SelecionarAcessos('rev', $usuario, $grupo, $id);
						$ArrayAdd = array();
						$ArrayAdd[] = array('RevVisualizar', $_TRA['Visualizar'], 'S');
						$ArrayAdd[] = array('RevAcesso', $_TRA['Acesso'], 'S');
						$ArrayAdd[] = array('RevInfo', $_TRA['info'], 'S');
						$ArrayAdd[] = array('RevMensagem', $_TRA['Mensagem'], 'S');
						$ArrayAdd[] = array('RevBloquear', $_TRA['bloquear'], 'S');
						$ArrayAdd[] = array('RevDesativar', $_TRA['desativar'], 'S');
						$ArrayAdd[] = array('RevEditar', $_TRA['editar'], 'S');
						$ArrayAdd[] = array('RevExcluir', $_TRA['excluir'], 'S');
						$ArrayAdd[] = array('RevAdicionar', $_TRA['Adicionar'], 'S');
						$ArrayAdd[] = array('RevUrldeTeste', $_TRA['udt'], 'S');
						$ArrayAdd[] = array('RevLogin', $_TRA['au'], 'S');
						$Inserir = InserirCheckbox($ArrayAdd, 'rev');
						
						if(!empty($Inserir)){						
						echo "<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['rev']."</label>
                            <div class=\"col-md-9\">
							".$Inserir."
                            </div>
                        </div>";
						}
						
						//Usuário
						$SelecionarAcessos = SelecionarAcessos('user', $usuario, $grupo, $id);
						$ArrayAdd = array();
						$ArrayAdd[] = array('UserVisualizar', $_TRA['Visualizar'], 'S');
						$ArrayAdd[] = array('UserInfo', $_TRA['info'], 'S');
						$ArrayAdd[] = array('UserMensagem', $_TRA['Mensagem'], 'S');
						$ArrayAdd[] = array('UserBloquear', $_TRA['bloquear'], $SelecionarAcessos['UserBloquear']);
						$ArrayAdd[] = array('UserEditar', $_TRA['editar'], 'S');
						$ArrayAdd[] = array('UserExcluir', $_TRA['excluir'], $SelecionarAcessos['UserExcluir']);
						$ArrayAdd[] = array('UserAdicionar', $_TRA['Adicionar'], 'S');
						$ArrayAdd[] = array('UserLogin', $_TRA['au'], 'S');
						$Inserir = InserirCheckbox($ArrayAdd, 'user');
						
						if(!empty($Inserir)){						
						echo "<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['user']."</label>
                            <div class=\"col-md-9\">
							".$Inserir."
                            </div>
                        </div>";
						}
						
						//Teste
						$SelecionarAcessos = SelecionarAcessos('teste', $usuario, $grupo, $id);
						$ArrayAdd = array();
						$ArrayAdd[] = array('TesteVisualizar', $_TRA['Visualizar'], 'S');
						$ArrayAdd[] = array('TesteInfo', $_TRA['info'], 'S');
						$ArrayAdd[] = array('TesteMensagem', $_TRA['Mensagem'], 'S');
						$ArrayAdd[] = array('TesteBloquear', $_TRA['bloquear'], 'S');
						$ArrayAdd[] = array('TesteEditar', $_TRA['editar'], 'S');
						$ArrayAdd[] = array('TesteExcluir', $_TRA['excluir'], 'S');
						$ArrayAdd[] = array('TesteAdicionar', $_TRA['Adicionar'], 'S');
						$ArrayAdd[] = array('TesteLogin', $_TRA['au'], 'S');
						$Inserir = InserirCheckbox($ArrayAdd, 'teste');
						
						if(!empty($Inserir)){						
						echo "<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['teste']."</label>
                            <div class=\"col-md-9\">
							".$Inserir."
                            </div>
                        </div>";
						}
						
						//Pagamentos
						$SelecionarAcessos = SelecionarAcessos('pagamentos', $usuario, $grupo, $id);
						$ArrayAdd = array();
						$ArrayAdd[] = array('PagamentoPagSeguro', $_TRA['PagSeguro'], $SelecionarAcessos['PagamentoPagSeguro']);
						$ArrayAdd[] = array('PagamentoPayPal', $_TRA['PayPal'], $SelecionarAcessos['PagamentoPayPal']);
						$ArrayAdd[] = array('PagamentoMercadoPago', $_TRA['MercadoPago'], $SelecionarAcessos['PagamentoMercadoPago']);
						$ArrayAdd[] = array('PagamentoContaBancaria', $_TRA['ContaBancaria'], 'S');
						$Inserir = InserirCheckbox($ArrayAdd, 'pagamentos');
						
						if(!empty($Inserir)){						
						echo "<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['Pagamentos']."</label>
                            <div class=\"col-md-9\">
							".$Inserir."
                            </div>
                        </div>";
						}
						
						//Status dos Usuários
						$SelecionarAcessos = SelecionarAcessos('status', $usuario, $grupo, $id);
						$ArrayAdd = array();
						$ArrayAdd[] = array('StatusOnline', $_TRA['Online'], 'S');
						$ArrayAdd[] = array('StatusDesconectado', $_TRA['Desconectado'], 'S');
						$ArrayAdd[] = array('StatusFalhado', $_TRA['Falhado'], 'S');
						$ArrayAdd[] = array('StatusLogs', $_TRA['Logs'], 'S');
						$ArrayAdd[] = array('StatusReshare', $_TRA['Reshare'], $SelecionarAcessos['StatusReshare']);
						$Inserir = InserirCheckbox($ArrayAdd, 'status');
						
						if(!empty($Inserir)){						
						echo "<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['sdu']."</label>
                            <div class=\"col-md-9\">
							".$Inserir."
                            </div>
                        </div>";
						}
						
						//Servidor CSP
						$SelecionarAcessos = SelecionarAcessos('servidorcsp', $usuario, $grupo, $id);
						$ArrayAdd = array();
						$ArrayAdd[] = array('ServidorcspVisualizar', $_TRA['Visualizar'], $SelecionarAcessos['ServidorcspVisualizar']);
						$ArrayAdd[] = array('ServidorcspAdicionar', $_TRA['Adicionar'], $SelecionarAcessos['ServidorcspAdicionar']);
						$ArrayAdd[] = array('ServidorcspConfig', $_TRA['config'], $SelecionarAcessos['ServidorcspConfig']);
						$ArrayAdd[] = array('ServidorcspInfo', $_TRA['informacoes'], $SelecionarAcessos['ServidorcspInfo']);
						$ArrayAdd[] = array('ServidorcspBloquear', $_TRA['bloquear'], $SelecionarAcessos['ServidorcspBloquear']);
						$ArrayAdd[] = array('ServidorcspEditar', $_TRA['editar'], $SelecionarAcessos['ServidorcspEditar']);
						$ArrayAdd[] = array('ServidorcspExcluir', $_TRA['excluir'], $SelecionarAcessos['ServidorcspExcluir']);
						$Inserir = InserirCheckbox($ArrayAdd, 'servidorcsp');
						
						if(!empty($Inserir)){
						echo "<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['SCSP']."</label>
                            <div class=\"col-md-9\">
							".$Inserir."
                            </div>
                        </div>";
						}
						
						//Perfil
						$SelecionarAcessos = SelecionarAcessos('perfil', $usuario, $grupo, $id);
						$ArrayAdd = array();
						$ArrayAdd[] = array('PerfilVisualizar', $_TRA['Visualizar'], 'S');
						$ArrayAdd[] = array('PerfilAdicionar', $_TRA['Adicionar'], $SelecionarAcessos['PerfilAdicionar']);
						$ArrayAdd[] = array('PerfilBloquear', $_TRA['bloquear'], $SelecionarAcessos['PerfilBloquear']);
						$ArrayAdd[] = array('PerfilEditar', $_TRA['editar'], $SelecionarAcessos['PerfilEditar']);
						$ArrayAdd[] = array('PerfilExcluir', $_TRA['excluir'], $SelecionarAcessos['PerfilExcluir']);
						$Inserir = InserirCheckbox($ArrayAdd, 'perfil');
						
						if(!empty($Inserir)){
						echo "<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['Perfil']."</label>
                            <div class=\"col-md-9\">
							".$Inserir."
                            </div>
                        </div>";
						}
						
						//Imagem Perfil
						$SelecionarAcessos = SelecionarAcessos('imagemperfil', $usuario, $grupo, $id);
						$ArrayAdd = array();
						$ArrayAdd[] = array('ImagemperfilVisualizar', $_TRA['Visualizar'], $SelecionarAcessos['ImagemperfilVisualizar']);
						$ArrayAdd[] = array('ImagemperfilAdicionar', $_TRA['Adicionar'], $SelecionarAcessos['ImagemperfilAdicionar']);
						$ArrayAdd[] = array('ImagemperfilExcluir', $_TRA['excluir'], $SelecionarAcessos['ImagemperfilExcluir']);
						$Inserir = InserirCheckbox($ArrayAdd, 'imagemperfil');
						
						if(!empty($Inserir)){
						echo "<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['ImagemP']."</label>
                            <div class=\"col-md-9\">
							".$Inserir."
                            </div>
                        </div>";
						}
						
						//Email Adicionar
						$SelecionarAcessos = SelecionarAcessos('email_adicionar', $usuario, $grupo, $id);
						$ArrayAdd = array();
						$ArrayAdd[] = array('EmailadicionarVisualizar', $_TRA['Visualizar'], 'S');
						$ArrayAdd[] = array('EmailadicionarAdicionar', $_TRA['Adicionar'], 'S');
						$ArrayAdd[] = array('EmailadicionarBloquear', $_TRA['bloquear'], 'S');
						$ArrayAdd[] = array('EmailadicionarEditar', $_TRA['editar'], 'S');
						$ArrayAdd[] = array('EmailadicionarExcluir', $_TRA['excluir'], 'S');
						$Inserir = InserirCheckbox($ArrayAdd, 'email_adicionar');
						
						if(!empty($Inserir)){
						echo "<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['EmailAdd']."</label>
                            <div class=\"col-md-9\">
							".$Inserir."
                            </div>
                        </div>";
						}
						
						//Email Modelo
						$SelecionarAcessos = SelecionarAcessos('email_modelo', $usuario, $grupo, $id);
						$ArrayAdd = array();
						$ArrayAdd[] = array('EmailModeloVisualizar', $_TRA['Visualizar'], 'S');
						$ArrayAdd[] = array('EmailModeloPreferencias', $_TRA['Preferencias'], 'S');
						$ArrayAdd[] = array('EmailModeloAdicionar', $_TRA['Adicionar'], 'S');
						$ArrayAdd[] = array('EmailModeloBloquear', $_TRA['bloquear'], 'S');
						$ArrayAdd[] = array('EmailModeloEditar', $_TRA['editar'], 'S');
						$ArrayAdd[] = array('EmailModeloExcluir', $_TRA['excluir'], 'S');
						$Inserir = InserirCheckbox($ArrayAdd, 'email_modelo');
						
						if(!empty($Inserir)){
						echo "<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['EmailModelo']."</label>
                            <div class=\"col-md-9\">
							".$Inserir."
                            </div>
                        </div>";
						}
						
						//SMS Adicionar
						$SelecionarAcessos = SelecionarAcessos('sms_adicionar', $usuario, $grupo, $id);
						$ArrayAdd = array();
						$ArrayAdd[] = array('SMSadicionarVisualizar', $_TRA['Visualizar'], $SelecionarAcessos['SMSadicionarVisualizar']);
						$ArrayAdd[] = array('SMSadicionarAdicionar', $_TRA['Adicionar'], $SelecionarAcessos['SMSadicionarAdicionar']);
						$ArrayAdd[] = array('SMSadicionarBloquear', $_TRA['bloquear'], $SelecionarAcessos['SMSadicionarBloquear']);
						$ArrayAdd[] = array('SMSadicionarEditar', $_TRA['editar'], $SelecionarAcessos['SMSadicionarEditar']);
						$ArrayAdd[] = array('SMSadicionarExcluir', $_TRA['excluir'], $SelecionarAcessos['SMSadicionarExcluir']);
						$Inserir = InserirCheckbox($ArrayAdd, 'sms_adicionar');
						
						if(!empty($Inserir)){
						echo "<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['smsa']."</label>
                            <div class=\"col-md-9\">
							".$Inserir."
                            </div>
                        </div>";
						}
						
						//SMS Modelo
						$SelecionarAcessos = SelecionarAcessos('sms_modelo', $usuario, $grupo, $id);
						$ArrayAdd = array();
						$ArrayAdd[] = array('SMSModeloVisualizar', $_TRA['Visualizar'], $SelecionarAcessos['SMSModeloVisualizar']);
						$ArrayAdd[] = array('SMSModeloPreferencias', $_TRA['Preferencias'], $SelecionarAcessos['SMSModeloPreferencias']);
						$ArrayAdd[] = array('SMSModeloAdicionar', $_TRA['Adicionar'], $SelecionarAcessos['SMSModeloAdicionar']);
						$ArrayAdd[] = array('SMSModeloBloquear', $_TRA['bloquear'], $SelecionarAcessos['SMSModeloBloquear']);
						$ArrayAdd[] = array('SMSModeloEditar', $_TRA['editar'], $SelecionarAcessos['SMSModeloEditar']);
						$ArrayAdd[] = array('SMSModeloExcluir', $_TRA['excluir'], $SelecionarAcessos['SMSModeloExcluir']);
						$Inserir = InserirCheckbox($ArrayAdd, 'sms_modelo');
						
						if(!empty($Inserir)){
						echo "<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['smsm']."</label>
                            <div class=\"col-md-9\">
							".$Inserir."
                            </div>
                        </div>";
						}
						
						//Tempo Teste
						$SelecionarAcessos = SelecionarAcessos('tempoteste', $usuario, $grupo, $id);
						$ArrayAdd = array();
						$ArrayAdd[] = array('TesteTempoVisualizar', $_TRA['Visualizar'], 'S');
						$ArrayAdd[] = array('TesteTempoAdicionar', $_TRA['Adicionar'], $SelecionarAcessos['TesteTempoAdicionar']);
						$ArrayAdd[] = array('TesteTempoBloquear', $_TRA['bloquear'], $SelecionarAcessos['TesteTempoBloquear']);
						$ArrayAdd[] = array('TesteTempoEditar', $_TRA['editar'], $SelecionarAcessos['TesteTempoEditar']);
						$ArrayAdd[] = array('TesteTempoExcluir', $_TRA['excluir'], $SelecionarAcessos['TesteTempoExcluir']);
						$Inserir = InserirCheckbox($ArrayAdd, 'tempoteste');
						
						if(!empty($Inserir)){
						echo "<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['tt']."</label>
                            <div class=\"col-md-9\">
							".$Inserir."
                            </div>
                        </div>";
						}
						
						//Template
						$SelecionarAcessos = SelecionarAcessos('template', $usuario, $grupo, $id);
						$ArrayAdd = array();
						$ArrayAdd[] = array('TemplateTema', $_TRA['temas'], $SelecionarAcessos['TemplateTema']);
						$ArrayAdd[] = array('TemplateInfo', $_TRA['info'], $SelecionarAcessos['TemplateInfo']);
						$ArrayAdd[] = array('TemplatePParede', $_TRA['papeldeparede'], $SelecionarAcessos['TemplatePParede']);
						$Inserir = InserirCheckbox($ArrayAdd, 'template');
						
						if(!empty($Inserir)){
						echo "<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['template']."</label>
                            <div class=\"col-md-9\">
							".$Inserir."
                            </div>
                        </div>";
						}
						
						//Opções
						$SelecionarAcessos = SelecionarAcessos('opcoes', $usuario, $grupo, $id);
						$ArrayAdd = array();
						$ArrayAdd[] = array('OpcoesExportar', $_TRA['Exportar'], $SelecionarAcessos['OpcoesExportar']);
						$ArrayAdd[] = array('OpcoesImportar', $_TRA['Importar'], 'S');
						$ArrayAdd[] = array('OpcoesVencimento', $_TRA['tp'], $SelecionarAcessos['OpcoesVencimento']);
						$ArrayAdd[] = array('OpcoesRelatorio', $_TRA['relatorio'], 'S');
						$ArrayAdd[] = array('OpcoesGrupoAcesso', $_TRA['gda'], $SelecionarAcessos['OpcoesGrupoAcesso']);
						$ArrayAdd[] = array('OpcoesMascaraURL', $_TRA['mdp'], 'S');
						$ArrayAdd[] = array('OpcoesLiberarComputador', $_TRA['lb'], $SelecionarAcessos['OpcoesLiberarComputador']);
						$ArrayAdd[] = array('OpcoesDesenvolvedor', $_TRA['Desenvolvedor'], $SelecionarAcessos['OpcoesDesenvolvedor']);
						$ArrayAdd[] = array('OpcoesCircular', $_TRA['ec'], $SelecionarAcessos['OpcoesCircular']);
						$ArrayAdd[] = array('OpcoesStatusServer', $_TRA['sds'], $SelecionarAcessos['OpcoesStatusServer']);
						$ArrayAdd[] = array('OpcoesBackup', $_TRA['Backup'], $SelecionarAcessos['OpcoesBackup']);
						$ArrayAdd[] = array('OpcoesEmailTemporario', $_TRA['etemp'], $SelecionarAcessos['OpcoesEmailTemporario']);
						$ArrayAdd[] = array('OpcoesEmailTeste', 'E-mail Teste', $SelecionarAcessos['OpcoesEmailTeste']);
						$ArrayAdd[] = array('OpcoesCupom', 'Cupom', $SelecionarAcessos['OpcoesCupom']);
						$Inserir = InserirCheckbox($ArrayAdd, 'opcoes');
						
						if(!empty($Inserir)){
						echo "<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['opcoes']."</label>
                            <div class=\"col-md-9\">
							".$Inserir."
                            </div>
                        </div>";
						}
						
						if($lista == "N"){
							echo "<input type=\"hidden\" name=\"usuario\" id=\"usuario\" value=\"".$usuario."\">";
							echo "<input type=\"hidden\" name=\"id\" id=\"id\" value=\"".$id."\">";
							echo "<input type=\"hidden\" name=\"grupo\" id=\"grupo\" value=\"".$grupo."\">";
						}
						else{
							echo "<input type=\"hidden\" name=\"usuario\" id=\"usuario\" value=\"".$UserList."\">";
						}
						
						echo "</span>";
	if($lista == "N"){
						echo "</form>
                    </div>
                    <div class=\"modal-footer\">
						<div id=\"StatusModal\"></div>
						<button type=\"button\" class=\"SalvarAcesso btn btn-danger\">".$_TRA['salvar']."</button>
                        <button type=\"button\" class=\"btn btn-default\" data-dismiss=\"modal\">".$_TRA['fechar']."</button>
                    </div>
                </div>
            </div>
        </div>";
	}
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
<script>
<?php
if($lista == "N"){
?>
$("#EditarModal").modal("show");

$(function(){  
 $("button.SalvarAcesso").click(function() { 
 
 		var Data = $(".FormAcessos").serialize();
		
		$('#StatusModal').html("<center><img src=\"img/owl/AjaxLoader.gif\"><br><br></center>");
		
		$.post('EnviarAdicionarAcesso.php', Data, function(resposta) {
				$("#StatusModal").html('');
				$("#StatusGeral").append(resposta);
		});
	});
});
<?php
}
if($grupo == "N"){
?>
$(function(){
	$(".FormAcessos select[name=EditarGrupo]").change(function(){
		
		var UserList = '<?php echo $usuario; ?>';
		var usuario = '<?php echo $CadUser; ?>';
		var id = $(this).val();
		var grupo = 'S';
		var lista = 'S';
		
		panel_refresh($(".FormAcessos"));
		
		$.post('ScriptModalAcessos.php', {usuario: usuario, id: id, grupo: grupo, lista: lista, UserList: UserList}, function(resposta) {
			
		setTimeout(panel_refresh($(".FormAcessos")),500);	
			
				$("#StatusLista").html('');
				$("#StatusLista").html(resposta);
		});
	});
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