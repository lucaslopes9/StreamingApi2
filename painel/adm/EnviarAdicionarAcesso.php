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

if ($_SERVER['REQUEST_METHOD'] == 'POST') {

$CadUserOnline = InfoUser(2);
$ArvoreAdminOnline = ArvoreAdminRev($CadUserOnline);
$ArvoreAdminOnline[] = $CadUserOnline;

$CadUser = (isset($_POST['usuario'])) ? $_POST['usuario'] : '';
$id = (isset($_POST['id'])) ? $_POST['id'] : NULL;
$grupo = (isset($_POST['grupo'])) ? $_POST['grupo'] : 'N';

if(empty($CadUser)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['cvfi'], "danger");
}
elseif(!in_array($CadUser, $ArvoreAdminOnline)) {
		echo MensagemAlerta($_TRA['erro'], str_replace("USER_TAG",$CadUser,$_TRA['npounpav']), "danger");
}
else{

//Noticias
$ArrayAdmin = array(
ConverterCheckbox(empty($_POST['NoticiaVisualizar']) ? "N" : $_POST['NoticiaVisualizar']),
ConverterCheckbox(empty($_POST['NoticiaEditar']) ? "N" : $_POST['NoticiaEditar']),
ConverterCheckbox(empty($_POST['NoticiaExcluir']) ? "N" : $_POST['NoticiaExcluir']),
ConverterCheckbox(empty($_POST['NoticiaAdicionar']) ? "N" : $_POST['NoticiaAdicionar'])
);
$TabelaAdmin = "noticias";
$ColunaAdmin = array('NoticiaVisualizar', 'NoticiaEditar', 'NoticiaExcluir', 'NoticiaAdicionar');
$AtualizarAcessos = AtualizarAcessos($ArrayAdmin, $TabelaAdmin, $ColunaAdmin, $CadUser, $grupo, $id);

	
//Administrador
$ArrayAdmin = array(
ConverterCheckbox(empty($_POST['AdminVisualizar']) ? "N" : $_POST['AdminVisualizar']),
ConverterCheckbox(empty($_POST['AdminAcesso']) ? "N" : $_POST['AdminAcesso']),
ConverterCheckbox(empty($_POST['AdminInfo']) ? "N" : $_POST['AdminInfo']),
ConverterCheckbox(empty($_POST['AdminMensagem']) ? "N" : $_POST['AdminMensagem']),
ConverterCheckbox(empty($_POST['AdminBloquear']) ? "N" : $_POST['AdminBloquear']),
ConverterCheckbox(empty($_POST['AdminDesativar']) ? "N" : $_POST['AdminDesativar']),
ConverterCheckbox(empty($_POST['AdminEditar']) ? "N" : $_POST['AdminEditar']),
ConverterCheckbox(empty($_POST['AdminExcluir']) ? "N" : $_POST['AdminExcluir']),
ConverterCheckbox(empty($_POST['AdminAdicionar']) ? "N" : $_POST['AdminAdicionar']),
ConverterCheckbox(empty($_POST['AdminLogin']) ? "N" : $_POST['AdminLogin'])
);
$TabelaAdmin = "admin";
$ColunaAdmin = array('AdminVisualizar', 'AdminAcesso', 'AdminInfo', 'AdminMensagem', 'AdminBloquear', 'AdminDesativar', 'AdminEditar', 'AdminExcluir', 'AdminAdicionar', 'AdminLogin');
$AtualizarAcessos = AtualizarAcessos($ArrayAdmin, $TabelaAdmin, $ColunaAdmin, $CadUser, $grupo, $id);

//Revendedor
$ArrayAdmin = array(
ConverterCheckbox(empty($_POST['RevVisualizar']) ? "N" : $_POST['RevVisualizar']),
ConverterCheckbox(empty($_POST['RevAcesso']) ? "N" : $_POST['RevAcesso']),
ConverterCheckbox(empty($_POST['RevInfo']) ? "N" : $_POST['RevInfo']),
ConverterCheckbox(empty($_POST['RevMensagem']) ? "N" : $_POST['RevMensagem']),
ConverterCheckbox(empty($_POST['RevBloquear']) ? "N" : $_POST['RevBloquear']),
ConverterCheckbox(empty($_POST['RevDesativar']) ? "N" : $_POST['RevDesativar']),
ConverterCheckbox(empty($_POST['RevEditar']) ? "N" : $_POST['RevEditar']),
ConverterCheckbox(empty($_POST['RevExcluir']) ? "N" : $_POST['RevExcluir']),
ConverterCheckbox(empty($_POST['RevAdicionar']) ? "N" : $_POST['RevAdicionar']),
ConverterCheckbox(empty($_POST['RevUrldeTeste']) ? "N" : $_POST['RevUrldeTeste']),
ConverterCheckbox(empty($_POST['RevLogin']) ? "N" : $_POST['RevLogin'])
);
$TabelaAdmin = "rev";
$ColunaAdmin = array('RevVisualizar', 'RevAcesso', 'RevInfo', 'RevMensagem', 'RevBloquear', 'RevDesativar', 'RevEditar', 'RevExcluir', 'RevAdicionar', 'RevUrldeTeste', 'RevLogin');
$AtualizarAcessos1 = AtualizarAcessos($ArrayAdmin, $TabelaAdmin, $ColunaAdmin, $CadUser, $grupo, $id);

//Usuário
$ArrayAdmin = array(
ConverterCheckbox(empty($_POST['UserVisualizar']) ? "N" : $_POST['UserVisualizar']),
ConverterCheckbox(empty($_POST['UserInfo']) ? "N" : $_POST['UserInfo']),
ConverterCheckbox(empty($_POST['UserMensagem']) ? "N" : $_POST['UserMensagem']),
ConverterCheckbox(empty($_POST['UserBloquear']) ? "N" : $_POST['UserBloquear']),
ConverterCheckbox(empty($_POST['UserEditar']) ? "N" : $_POST['UserEditar']),
ConverterCheckbox(empty($_POST['UserExcluir']) ? "N" : $_POST['UserExcluir']),
ConverterCheckbox(empty($_POST['UserAdicionar']) ? "N" : $_POST['UserAdicionar']),
ConverterCheckbox(empty($_POST['UserLogin']) ? "N" : $_POST['UserLogin'])
);
$TabelaAdmin = "user";
$ColunaAdmin = array('UserVisualizar', 'UserInfo', 'UserMensagem', 'UserBloquear', 'UserEditar', 'UserExcluir', 'UserAdicionar', 'UserLogin');
$AtualizarAcessos2 = AtualizarAcessos($ArrayAdmin, $TabelaAdmin, $ColunaAdmin, $CadUser, $grupo, $id);

//Teste
$ArrayAdmin = array(
ConverterCheckbox(empty($_POST['TesteVisualizar']) ? "N" : $_POST['TesteVisualizar']),
ConverterCheckbox(empty($_POST['TesteInfo']) ? "N" : $_POST['TesteInfo']),
ConverterCheckbox(empty($_POST['TesteMensagem']) ? "N" : $_POST['TesteMensagem']),
ConverterCheckbox(empty($_POST['TesteBloquear']) ? "N" : $_POST['TesteBloquear']),
ConverterCheckbox(empty($_POST['TesteEditar']) ? "N" : $_POST['TesteEditar']),
ConverterCheckbox(empty($_POST['TesteExcluir']) ? "N" : $_POST['TesteExcluir']),
ConverterCheckbox(empty($_POST['TesteAdicionar']) ? "N" : $_POST['TesteAdicionar']),
ConverterCheckbox(empty($_POST['TesteLogin']) ? "N" : $_POST['TesteLogin'])
);
$TabelaAdmin = "teste";
$ColunaAdmin = array('TesteVisualizar', 'TesteInfo', 'TesteMensagem', 'TesteBloquear', 'TesteEditar', 'TesteExcluir', 'TesteAdicionar', 'TesteLogin');
$AtualizarAcessos3 = AtualizarAcessos($ArrayAdmin, $TabelaAdmin, $ColunaAdmin, $CadUser, $grupo, $id);

//Servidor CSP
$ArrayAdmin = array(
ConverterCheckbox(empty($_POST['ServidorcspVisualizar']) ? "N" : $_POST['ServidorcspVisualizar']),
ConverterCheckbox(empty($_POST['ServidorcspAdicionar']) ? "N" : $_POST['ServidorcspAdicionar']),
ConverterCheckbox(empty($_POST['ServidorcspConfig']) ? "N" : $_POST['ServidorcspConfig']),
ConverterCheckbox(empty($_POST['ServidorcspInfo']) ? "N" : $_POST['ServidorcspInfo']),
ConverterCheckbox(empty($_POST['ServidorcspBloquear']) ? "N" : $_POST['ServidorcspBloquear']),
ConverterCheckbox(empty($_POST['ServidorcspEditar']) ? "N" : $_POST['ServidorcspEditar']),
ConverterCheckbox(empty($_POST['ServidorcspExcluir']) ? "N" : $_POST['ServidorcspExcluir'])
);
$TabelaAdmin = "servidorcsp";
$ColunaAdmin = array('ServidorcspVisualizar', 'ServidorcspAdicionar', 'ServidorcspConfig', 'ServidorcspInfo', 'ServidorcspBloquear', 'ServidorcspEditar', 'ServidorcspExcluir');
$AtualizarAcessos4 = AtualizarAcessos($ArrayAdmin, $TabelaAdmin, $ColunaAdmin, $CadUser, $grupo, $id);

//Perfil
$ArrayAdmin = array(
ConverterCheckbox(empty($_POST['PerfilVisualizar']) ? "N" : $_POST['PerfilVisualizar']),
ConverterCheckbox(empty($_POST['PerfilAdicionar']) ? "N" : $_POST['PerfilAdicionar']),
ConverterCheckbox(empty($_POST['PerfilBloquear']) ? "N" : $_POST['PerfilBloquear']),
ConverterCheckbox(empty($_POST['PerfilEditar']) ? "N" : $_POST['PerfilEditar']),
ConverterCheckbox(empty($_POST['PerfilExcluir']) ? "N" : $_POST['PerfilExcluir'])
);
$TabelaAdmin = "perfil";
$ColunaAdmin = array('PerfilVisualizar', 'PerfilAdicionar', 'PerfilBloquear', 'PerfilEditar', 'PerfilExcluir');
$AtualizarAcessos5 = AtualizarAcessos($ArrayAdmin, $TabelaAdmin, $ColunaAdmin, $CadUser, $grupo, $id);

//Imagem Perfil
$ArrayAdmin = array(
ConverterCheckbox(empty($_POST['ImagemperfilVisualizar']) ? "N" : $_POST['ImagemperfilVisualizar']),
ConverterCheckbox(empty($_POST['ImagemperfilAdicionar']) ? "N" : $_POST['ImagemperfilAdicionar']),
ConverterCheckbox(empty($_POST['ImagemperfilExcluir']) ? "N" : $_POST['ImagemperfilExcluir'])
);
$TabelaAdmin = "imagemperfil";
$ColunaAdmin = array('ImagemperfilVisualizar', 'ImagemperfilAdicionar', 'ImagemperfilExcluir');
$AtualizarAcessos6 = AtualizarAcessos($ArrayAdmin, $TabelaAdmin, $ColunaAdmin, $CadUser, $grupo, $id);

//Email Adicionar
$ArrayAdmin = array(
ConverterCheckbox(empty($_POST['EmailadicionarVisualizar']) ? "N" : $_POST['EmailadicionarVisualizar']),
ConverterCheckbox(empty($_POST['EmailadicionarAdicionar']) ? "N" : $_POST['EmailadicionarAdicionar']),
ConverterCheckbox(empty($_POST['EmailadicionarBloquear']) ? "N" : $_POST['EmailadicionarBloquear']),
ConverterCheckbox(empty($_POST['EmailadicionarEditar']) ? "N" : $_POST['EmailadicionarEditar']),
ConverterCheckbox(empty($_POST['EmailadicionarExcluir']) ? "N" : $_POST['EmailadicionarExcluir'])	
);
$TabelaAdmin = "email_adicionar";
$ColunaAdmin = array('EmailadicionarVisualizar', 'EmailadicionarAdicionar', 'EmailadicionarBloquear', 'EmailadicionarEditar', 'EmailadicionarExcluir');
$AtualizarAcessos7 = AtualizarAcessos($ArrayAdmin, $TabelaAdmin, $ColunaAdmin, $CadUser, $grupo, $id);

//Email Modelo
$ArrayAdmin = array(
ConverterCheckbox(empty($_POST['EmailModeloVisualizar']) ? "N" : $_POST['EmailModeloVisualizar']),
ConverterCheckbox(empty($_POST['EmailModeloPreferencias']) ? "N" : $_POST['EmailModeloPreferencias']),
ConverterCheckbox(empty($_POST['EmailModeloAdicionar']) ? "N" : $_POST['EmailModeloAdicionar']),
ConverterCheckbox(empty($_POST['EmailModeloBloquear']) ? "N" : $_POST['EmailModeloBloquear']),
ConverterCheckbox(empty($_POST['EmailModeloEditar']) ? "N" : $_POST['EmailModeloEditar']),
ConverterCheckbox(empty($_POST['EmailModeloExcluir']) ? "N" : $_POST['EmailModeloExcluir'])	
);
$TabelaAdmin = "email_modelo";
$ColunaAdmin = array('EmailModeloVisualizar', 'EmailModeloPreferencias', 'EmailModeloAdicionar', 'EmailModeloBloquear', 'EmailModeloEditar', 'EmailModeloExcluir');
$AtualizarAcessos8 = AtualizarAcessos($ArrayAdmin, $TabelaAdmin, $ColunaAdmin, $CadUser, $grupo, $id);

//Tempo Teste
$ArrayAdmin = array(
ConverterCheckbox(empty($_POST['TesteTempoVisualizar']) ? "N" : $_POST['TesteTempoVisualizar']),
ConverterCheckbox(empty($_POST['TesteTempoAdicionar']) ? "N" : $_POST['TesteTempoAdicionar']),
ConverterCheckbox(empty($_POST['TesteTempoBloquear']) ? "N" : $_POST['TesteTempoBloquear']),
ConverterCheckbox(empty($_POST['TesteTempoEditar']) ? "N" : $_POST['TesteTempoEditar']),
ConverterCheckbox(empty($_POST['TesteTempoExcluir']) ? "N" : $_POST['TesteTempoExcluir'])	
);
$TabelaAdmin = "tempoteste";
$ColunaAdmin = array('TesteTempoVisualizar', 'TesteTempoAdicionar', 'TesteTempoBloquear', 'TesteTempoEditar', 'TesteTempoExcluir');
$AtualizarAcessos9 = AtualizarAcessos($ArrayAdmin, $TabelaAdmin, $ColunaAdmin, $CadUser, $grupo, $id);

//SMS Adicionar
$ArrayAdmin = array(
ConverterCheckbox(empty($_POST['SMSadicionarVisualizar']) ? "N" : $_POST['SMSadicionarVisualizar']),
ConverterCheckbox(empty($_POST['SMSadicionarAdicionar']) ? "N" : $_POST['SMSadicionarAdicionar']),
ConverterCheckbox(empty($_POST['SMSadicionarBloquear']) ? "N" : $_POST['SMSadicionarBloquear']),
ConverterCheckbox(empty($_POST['SMSadicionarEditar']) ? "N" : $_POST['SMSadicionarEditar']),
ConverterCheckbox(empty($_POST['SMSadicionarExcluir']) ? "N" : $_POST['SMSadicionarExcluir'])	
);
$TabelaAdmin = "sms_adicionar";
$ColunaAdmin = array('SMSadicionarVisualizar', 'SMSadicionarAdicionar', 'SMSadicionarBloquear', 'SMSadicionarEditar', 'SMSadicionarExcluir');
$AtualizarAcessos10 = AtualizarAcessos($ArrayAdmin, $TabelaAdmin, $ColunaAdmin, $CadUser, $grupo, $id);

//SMS Modelo
$ArrayAdmin = array(
ConverterCheckbox(empty($_POST['SMSModeloVisualizar']) ? "N" : $_POST['SMSModeloVisualizar']),
ConverterCheckbox(empty($_POST['SMSModeloPreferencias']) ? "N" : $_POST['SMSModeloPreferencias']),
ConverterCheckbox(empty($_POST['SMSModeloAdicionar']) ? "N" : $_POST['SMSModeloAdicionar']),
ConverterCheckbox(empty($_POST['SMSModeloBloquear']) ? "N" : $_POST['SMSModeloBloquear']),
ConverterCheckbox(empty($_POST['SMSModeloEditar']) ? "N" : $_POST['SMSModeloEditar']),
ConverterCheckbox(empty($_POST['SMSModeloExcluir']) ? "N" : $_POST['SMSModeloExcluir'])	
);
$TabelaAdmin = "sms_modelo";
$ColunaAdmin = array('SMSModeloVisualizar', 'SMSModeloPreferencias', 'SMSModeloAdicionar', 'SMSModeloBloquear', 'SMSModeloEditar', 'SMSModeloExcluir');
$AtualizarAcessos11 = AtualizarAcessos($ArrayAdmin, $TabelaAdmin, $ColunaAdmin, $CadUser, $grupo, $id);

//Template
$ArrayAdmin = array(
ConverterCheckbox(empty($_POST['TemplateTema']) ? "N" : $_POST['TemplateTema']),
ConverterCheckbox(empty($_POST['TemplateInfo']) ? "N" : $_POST['TemplateInfo']),
ConverterCheckbox(empty($_POST['TemplatePParede']) ? "N" : $_POST['TemplatePParede'])	
);
$TabelaAdmin = "template";
$ColunaAdmin = array('TemplateTema', 'TemplateInfo', 'TemplatePParede');
$AtualizarAcessos12 = AtualizarAcessos($ArrayAdmin, $TabelaAdmin, $ColunaAdmin, $CadUser, $grupo, $id);

//Opções
$ArrayAdmin = array(
ConverterCheckbox(empty($_POST['OpcoesExportar']) ? "N" : $_POST['OpcoesExportar']),
ConverterCheckbox(empty($_POST['OpcoesImportar']) ? "N" : $_POST['OpcoesImportar']),
ConverterCheckbox(empty($_POST['OpcoesVencimento']) ? "N" : $_POST['OpcoesVencimento']),
ConverterCheckbox(empty($_POST['OpcoesRelatorio']) ? "N" : $_POST['OpcoesRelatorio']),
ConverterCheckbox(empty($_POST['OpcoesGrupoAcesso']) ? "N" : $_POST['OpcoesGrupoAcesso']),
ConverterCheckbox(empty($_POST['OpcoesMascaraURL']) ? "N" : $_POST['OpcoesMascaraURL']),
ConverterCheckbox(empty($_POST['OpcoesLiberarComputador']) ? "N" : $_POST['OpcoesLiberarComputador']),
ConverterCheckbox(empty($_POST['OpcoesDesenvolvedor']) ? "N" : $_POST['OpcoesDesenvolvedor']),
ConverterCheckbox(empty($_POST['OpcoesCircular']) ? "N" : $_POST['OpcoesCircular']),
ConverterCheckbox(empty($_POST['OpcoesStatusServer']) ? "N" : $_POST['OpcoesStatusServer']),
ConverterCheckbox(empty($_POST['OpcoesBackup']) ? "N" : $_POST['OpcoesBackup']),
ConverterCheckbox(empty($_POST['OpcoesEmailTemporario']) ? "N" : $_POST['OpcoesEmailTemporario']),
ConverterCheckbox(empty($_POST['OpcoesEmailTeste']) ? "N" : $_POST['OpcoesEmailTeste']),
ConverterCheckbox(empty($_POST['OpcoesCupom']) ? "N" : $_POST['OpcoesCupom'])
);
$TabelaAdmin = "opcoes";
$ColunaAdmin = array('OpcoesExportar', 'OpcoesImportar', 'OpcoesVencimento', 'OpcoesRelatorio', 'OpcoesGrupoAcesso', 'OpcoesMascaraURL', 'OpcoesLiberarComputador', 'OpcoesDesenvolvedor', 'OpcoesCircular', 'OpcoesStatusServer', 'OpcoesBackup', 'OpcoesEmailTemporario', 'OpcoesEmailTeste', 'OpcoesCupom');
$AtualizarAcessos13 = AtualizarAcessos($ArrayAdmin, $TabelaAdmin, $ColunaAdmin, $CadUser, $grupo, $id);

//Status dos Clientes
$ArrayAdmin = array(
ConverterCheckbox(empty($_POST['StatusOnline']) ? "N" : $_POST['StatusOnline']),
ConverterCheckbox(empty($_POST['StatusDesconectado']) ? "N" : $_POST['StatusDesconectado']),
ConverterCheckbox(empty($_POST['StatusFalhado']) ? "N" : $_POST['StatusFalhado']),
ConverterCheckbox(empty($_POST['StatusLogs']) ? "N" : $_POST['StatusLogs']),
ConverterCheckbox(empty($_POST['StatusReshare']) ? "N" : $_POST['StatusReshare'])
);
$TabelaAdmin = "status";
$ColunaAdmin = array('StatusOnline', 'StatusDesconectado', 'StatusFalhado', 'StatusLogs', 'StatusReshare');
$AtualizarAcessos14 = AtualizarAcessos($ArrayAdmin, $TabelaAdmin, $ColunaAdmin, $CadUser, $grupo, $id);

//Pagamentos
$ArrayAdmin = array(
ConverterCheckbox(empty($_POST['PagamentoPagSeguro']) ? "N" : $_POST['PagamentoPagSeguro']),
ConverterCheckbox(empty($_POST['PagamentoPayPal']) ? "N" : $_POST['PagamentoPayPal']),
ConverterCheckbox(empty($_POST['PagamentoMercadoPago']) ? "N" : $_POST['PagamentoMercadoPago']),
ConverterCheckbox(empty($_POST['PagamentoContaBancaria']) ? "N" : $_POST['PagamentoContaBancaria'])
);
$TabelaAdmin = "pagamentos";
$ColunaAdmin = array('PagamentoPagSeguro', 'PagamentoPayPal', 'PagamentoMercadoPago', 'PagamentoContaBancaria');
$AtualizarAcessos15 = AtualizarAcessos($ArrayAdmin, $TabelaAdmin, $ColunaAdmin, $CadUser, $grupo, $id);

if($AtualizarAcessos == false){
	echo MensagemAlerta($_TRA['erro'], $_TRA['erropro'], "danger", $_SERVER['HTTP_REFERER']);
}
elseif($AtualizarAcessos2 == false){
	echo MensagemAlerta($_TRA['erro'], $_TRA['erropro'], "danger", $_SERVER['HTTP_REFERER']);
}
elseif($AtualizarAcessos3 == false){
	echo MensagemAlerta($_TRA['erro'], $_TRA['erropro'], "danger", $_SERVER['HTTP_REFERER']);
}
elseif($AtualizarAcessos4 == false){
	echo MensagemAlerta($_TRA['erro'], $_TRA['erropro'], "danger", $_SERVER['HTTP_REFERER']);
}
elseif($AtualizarAcessos5 == false){
	echo MensagemAlerta($_TRA['erro'], $_TRA['erropro'], "danger", $_SERVER['HTTP_REFERER']);
}
elseif($AtualizarAcessos6 == false){
	echo MensagemAlerta($_TRA['erro'], $_TRA['erropro'], "danger", $_SERVER['HTTP_REFERER']);
}
elseif($AtualizarAcessos7 == false){
	echo MensagemAlerta($_TRA['erro'], $_TRA['erropro'], "danger", $_SERVER['HTTP_REFERER']);
}
elseif($AtualizarAcessos8 == false){
	echo MensagemAlerta($_TRA['erro'], $_TRA['erropro'], "danger", $_SERVER['HTTP_REFERER']);
}
elseif($AtualizarAcessos9 == false){
	echo MensagemAlerta($_TRA['erro'], $_TRA['erropro'], "danger", $_SERVER['HTTP_REFERER']);
}
elseif($AtualizarAcessos10 == false){
	echo MensagemAlerta($_TRA['erro'], $_TRA['erropro'], "danger", $_SERVER['HTTP_REFERER']);
}
elseif($AtualizarAcessos11 == false){
	echo MensagemAlerta($_TRA['erro'], $_TRA['erropro'], "danger", $_SERVER['HTTP_REFERER']);
}
elseif($AtualizarAcessos12 == false){
	echo MensagemAlerta($_TRA['erro'], $_TRA['erropro'], "danger", $_SERVER['HTTP_REFERER']);
}
elseif($AtualizarAcessos13 == false){
	echo MensagemAlerta($_TRA['erro'], $_TRA['erropro'], "danger", $_SERVER['HTTP_REFERER']);
}
elseif($AtualizarAcessos14 == false){
	echo MensagemAlerta($_TRA['erro'], $_TRA['erropro'], "danger", $_SERVER['HTTP_REFERER']);
}
elseif($AtualizarAcessos15 == false){
	echo MensagemAlerta($_TRA['erro'], $_TRA['erropro'], "danger", $_SERVER['HTTP_REFERER']);
}
else{
	echo MensagemAlerta($_TRA['sucesso'], $_TRA['alcs'], "success", $_SERVER['HTTP_REFERER']);
}


}
}

}else{
	echo Redirecionar('index.php');
}
}else{
	echo Redirecionar('login.php');
}	
?>