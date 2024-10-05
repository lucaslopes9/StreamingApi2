<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;
global $painel_user;
$AcessoUser = InfoUser(3);
$VersaoPainel = VersaoPainel();

$PrePagoSessao = empty($_SESSION['PrePago']) ? "N" : $_SESSION['PrePago'];

$VerificarInfoOnline = VerificarInfoOnline();
$usuario = InfoUser(2);
$Foto = Foto($VerificarInfoOnline[3]);
$ExibirNome = empty($VerificarInfoOnline[0]) && empty($VerificarInfoOnline[1]) ? $usuario : $VerificarInfoOnline[0]."&nbsp;".$VerificarInfoOnline[1];

//Administrador
$Coluna_1 = array('AdminVisualizar');
$VerificarAcesso_1 = VerificarAcesso('admin', $Coluna_1);
$AdminVisualizar = $VerificarAcesso_1[0];

//Servidor CSP
$Coluna_2 = array('ServidorcspVisualizar');
$VerificarAcesso_2 = VerificarAcesso('servidorcsp', $Coluna_2);
$ServidorcspVisualizar = $VerificarAcesso_2[0];

//Perfil
$Coluna_3 = array('PerfilVisualizar');
$VerificarAcesso_3 = VerificarAcesso('perfil', $Coluna_3);
$PerfilVisualizar = $VerificarAcesso_3[0];

//Imagem Perfil
$Coluna_4 = array('ImagemperfilVisualizar');
$VerificarAcesso_4 = VerificarAcesso('imagemperfil', $Coluna_4);
$ImagemperfilVisualizar = $VerificarAcesso_4[0];

//Email Adicionar
$Coluna_5 = array('EmailadicionarVisualizar');
$VerificarAcesso_5 = VerificarAcesso('email_adicionar', $Coluna_5);
$EmailadicionarVisualizar = $VerificarAcesso_5[0];

//Email Modelo
$Coluna_6 = array('EmailModeloVisualizar');
$VerificarAcesso_6 = VerificarAcesso('email_modelo', $Coluna_6);
$EmailModeloVisualizar = $VerificarAcesso_6[0];

//Template
$Coluna_7 = array('TemplateTema','TemplateInfo','TemplatePParede');
$VerificarAcesso_7 = VerificarAcesso('template', $Coluna_7);
$TemplateTema = $VerificarAcesso_7[0];
$TemplateInfo = $VerificarAcesso_7[1];
$TemplatePParede = $VerificarAcesso_7[2];

//Revendedor
$Coluna_8 = array('RevVisualizar');
$VerificarAcesso_8 = VerificarAcesso('rev', $Coluna_8);
$RevVisualizar = $VerificarAcesso_8[0];

//Usuário
$Coluna_9 = array('UserVisualizar');
$VerificarAcesso_9 = VerificarAcesso('user', $Coluna_9);
$UserVisualizar = $VerificarAcesso_9[0];

//Teste
$Coluna_10 = array('TesteVisualizar');
$VerificarAcesso_10 = VerificarAcesso('teste', $Coluna_10);
$TesteVisualizar = $VerificarAcesso_10[0];

//SMS Adicionar
$Coluna_11 = array('SMSadicionarVisualizar');
$VerificarAcesso_11 = VerificarAcesso('sms_adicionar', $Coluna_11);
$SMSadicionarVisualizar = $VerificarAcesso_11[0];

//SMS Modelo
$Coluna_12 = array('SMSModeloVisualizar');
$VerificarAcesso_12 = VerificarAcesso('sms_modelo', $Coluna_12);
$SMSModeloVisualizar = $VerificarAcesso_12[0];

//Tempo Teste
$Coluna_13 = array('TesteTempoVisualizar');
$VerificarAcesso_13 = VerificarAcesso('tempoteste', $Coluna_13);
$TesteTempoVisualizar = $VerificarAcesso_13[0];

//Opções
$Coluna_14 = array('OpcoesExportar', 'OpcoesImportar', 'OpcoesVencimento', 'OpcoesRelatorio', 'OpcoesGrupoAcesso', 'OpcoesMascaraURL', 'OpcoesLiberarComputador', 'OpcoesCircular', 'OpcoesBackup', 'OpcoesEmailTemporario');
$VerificarAcesso_14 = VerificarAcesso('opcoes', $Coluna_14);
$OpcoesExportar = $VerificarAcesso_14[0];
$OpcoesImportar = $VerificarAcesso_14[1];
$OpcoesVencimento = $VerificarAcesso_14[2];
$OpcoesRelatorio = $VerificarAcesso_14[3];
$OpcoesGrupoAcesso = $VerificarAcesso_14[4];
$OpcoesMascaraURL = $VerificarAcesso_14[5];
$OpcoesLiberarComputador = $VerificarAcesso_14[6];
$OpcoesCircular = $VerificarAcesso_14[7];
$OpcoesBackup = $VerificarAcesso_14[8];
$OpcoesEmailTemporario = $VerificarAcesso_14[9];

//Status
$Coluna_15 = array('StatusOnline', 'StatusDesconectado', 'StatusFalhado', 'StatusLogs', 'StatusReshare');
$VerificarAcesso_15 = VerificarAcesso('status', $Coluna_15);
$StatusOnline = $VerificarAcesso_15[0];
$StatusDesconectado = $VerificarAcesso_15[1];
$StatusFalhado = $VerificarAcesso_15[2];
$StatusLogs = $VerificarAcesso_15[3];
$StatusReshare = $VerificarAcesso_15[4];

//Pagamentos
$Coluna_16 = array('PagamentoPagSeguro', 'PagamentoPayPal', 'PagamentoMercadoPago', 'PagamentoContaBancaria');
$VerificarAcesso_16 = VerificarAcesso('pagamentos', $Coluna_16);
$PagamentoPagSeguro = $VerificarAcesso_16[0];
$PagamentoPayPal = $VerificarAcesso_16[1];
$PagamentoMercadoPago = $VerificarAcesso_16[2];
$PagamentoContaBancaria = $VerificarAcesso_16[3];
?>

<div class="page-sidebar">
                <!-- START X-NAVIGATION -->
                <ul class="x-navigation">
                    <li class="xn-logo">
                        <a href="index.php"><span class="TituloPainel"><?php echo $_SESSION['NomePainel']; ?></span></a>
                        <a href="#" class="x-navigation-control"></a>
                    </li>
                    <li class="xn-profile">
                        <a href="#" class="profile-mini">
                            <img src="<?php echo $Foto; ?>" alt="<?php echo $ExibirNome; ?>"/>
                        </a>
                        <div class="profile">
                            <div class="profile-image" id="profile-image"></div>
                            <div class="profile-data">
                                <div class="profile-data-name"><?php echo $ExibirNome; ?></div>
                                <?php if(!empty($VerificarInfoOnline[2])) echo "<div class=\"profile-data-title\">".$VerificarInfoOnline[2]."</div>"; ?>
                                <div class="profile-data-title"><?php echo NivelAcesso(); ?></div>
                            </div>
                            <div class="profile-controls">
                                <a href="index.php?p=editar-perfil" class="profile-control-left"><span class="fa fa-info"></span></a>
                                <a href="index.php?p=suporte" class="profile-control-right"><span class="fa fa-envelope"></span></a>
                            </div>
                        </div>                                                                        
                    </li>
                     
                     <?php
					 echo "<li class=\"xn-title\">".$_TRA['SBV']."</li>
					
					<li>
                        <a href=\"index.php?p=inicio\"><span class=\"fa fa-home\"></span> <span class=\"xn-text\">".$_TRA['inicio']."</span></a>
                    </li>
					";
					 
					 //Gerenciador de Grupo
					 if( ($AdminVisualizar == 'S') || ($RevVisualizar == 'S') || ($UserVisualizar == 'S') || ($TesteVisualizar == 'S') ){ 
					 ?>
                     <li class="xn-title"><?php echo $_TRA['gdg']; ?></li>
                       
                    <?php
					if( ($AdminVisualizar == 'S') || ($RevVisualizar == 'S') || ($UserVisualizar == 'S') || ($TesteVisualizar == 'S') ){ 
					?>
                    <li>
                        <a href="index.php?p=grupos"><span class="fa fa-users"></span> <span class="xn-text">Todos</span></a>
                    </li>
                    <?php 
					}
					if($AdminVisualizar == 'S'){ 
					?>   
                    <li><a href="index.php?p=administrador"><span class="fa fa-user"></span> <span class="xn-text"><?php echo $_TRA['admin']; ?></span></a></li>
                    <?php 
					} 
					if($RevVisualizar == 'S'){ 
					?>
                   <li>
                        <a href="index.php?p=revendedor"><span class="fa fa-user"></span> <span class="xn-text"><?php echo $_TRA['rev']; ?></span></a>
                   </li> 
                   <?php
					}
					if($UserVisualizar == 'S'){ 
				   ?>
                   <li>
                        <a href="index.php?p=usuario"><span class="fa fa-user"></span> <span class="xn-text"><?php echo $_TRA['user']; ?></span></a>
                    </li>
                    <?php
					}
					if($TesteVisualizar == 'S'){ 
					?>
                    <li>
                        <a href="index.php?p=teste"><span class="fa fa-user"></span> <span class="xn-text"><?php echo $_TRA['teste']; ?></span></a>
                    </li>
                    <?php
					}
					?>

                    <?php
					}
	
					if( ($AcessoUser == 1) || ($AcessoUser == 2) ){
						
					//Redes Sociais
					?>
					<li class="xn-title">Redes Sociais</li>
					
					<li class="xn-openable">
                    <a href="#"><span class="fa fa-th-large"></span> <span class="xn-text">Redes Sociais</span></a>
                    <ul> 
						
					<li>
                        <a href="index.php?p=whatsapp"><span class="fa fa-whatsapp"></span> WhatsApp</a>
                    </li>
                    
                    <li>
                        <a href="index.php?p=telegram"><span class="fa fa-telegram"></span> Telegram</a>
                    </li>
                    
                    <li>
                        <a href="index.php?p=facebook"><span class="fa fa-facebook"></span> Facebook</a>
                    </li>
                    
                    </ul>
                    </li>
					
					<?php
					}
	
					//Pagamentos
					if( ($PagamentoPagSeguro == 'S') || ($PagamentoPayPal == 'S') || ($PagamentoMercadoPago == 'S') || ($PagamentoContaBancaria == 'S') || ($AcessoUser == 2) && ($PrePagoSessao == "S") || ($AcessoUser == 3) || ($AcessoUser == 4) ){ 
					?>
					<li class="xn-title"><?php echo $_TRA['Pagamentos']; ?></li>
                    <?php
					}
					
					if( ($PrePagoSessao == "S") || ($AcessoUser == 3) || ($AcessoUser == 4) ){
					?>
                    <li>
                        <a href="index.php?p=comprar"><span class="fa fa-usd"></span> <span class="xn-text"><?php echo $_TRA['Comprar']; ?></span></a>
                    </li>
                    <?php
					}
					
					if( ($AcessoUser == 2) && ($PrePagoSessao == "S") || ($AcessoUser == 3) || ($AcessoUser == 4) ){
					?>
                    <li>
                        <a href="index.php?p=compras"><span class="fa fa-credit-card"></span> <span class="xn-text"><?php echo $_TRA['mco']; ?></span></a>
                    </li>
                    <?php
					}
					
					if( ($PagamentoPagSeguro == 'S') || ($PagamentoPayPal == 'S') || ($PagamentoMercadoPago == 'S') || ($PagamentoContaBancaria == 'S') ){ 
					
					if( ($AcessoUser == 1) || ($AcessoUser == 2) ){
					?>
                    <li>
                        <a href="index.php?p=vendas"><span class="fa fa-credit-card"></span> <span class="xn-text"><?php echo $_TRA['mve']; ?></span></a>
                    </li>
                    <?php
					}
					
					?>
                    <li>
                        <a href="index.php?p=criar-plano"><span class="fa fa-wrench"></span> <span class="xn-text"><?php echo $_TRA['CriarPlano']; ?></span></a>
                    </li>
                    
                    <li class="xn-openable">
                    <a href="#"><span class="fa fa-money"></span> <span class="xn-text"><?php echo $_TRA['FormadePagamento']; ?></span></a>
                    <ul> 
                 	<?php
					if($PagamentoPagSeguro == 'S'){
					?>
                    <li><a href="index.php?p=pagseguro"><span class="fa fa-chevron-right"></span> <?php echo $_TRA['PagSeguro']; ?></a></li>
                    <?php
					}
					if($PagamentoPayPal == 'S'){
					?>
                    <li><a href="index.php?p=paypal"><span class="fa fa-chevron-right"></span> <?php echo $_TRA['PayPal']; ?></a></li> 
                  	<?php
					}
					if($PagamentoMercadoPago == 'S'){
					?>
                    <li><a href="index.php?p=mercadopago"><span class="fa fa-chevron-right"></span> <?php echo $_TRA['MercadoPago']; ?></a></li>
                    <?php
					}
					if($PagamentoContaBancaria == 'S'){
					?>
                    <li><a href="index.php?p=contabancaria"><span class="fa fa-chevron-right"></span> <?php echo $_TRA['ContaBancaria']; ?></a></li>
					<?php
					}
					?>
        			</ul>
                    </li>
                    
					<?php
					 }
					 //Status
					 if( ($StatusOnline == 'S') || ($StatusDesconectado == 'S') || ($StatusFalhado == 'S') || ($StatusLogs == 'S') || ($StatusReshare == 'S') ){ 
					 ?>
                     <li class="xn-title"><?php echo $_TRA['Status']; ?></li>
                     
                     <li class="xn-openable">
                     <a href="#"><span class="fa fa-retweet"></span> <span class="xn-text"><?php echo $_TRA['sdu']; ?></span></a>
                     <ul> 
                        
                    <?php 
					if($StatusOnline == 'S'){ 
					?>   
                    <li><a href="index.php?p=status-online"><span class="fa fa-circle"></span> <?php echo $_TRA['Online']; ?></a></li>
                    <?php 
					} 
					if($StatusDesconectado == 'S'){ 
					?>
                   <li>
                        <a href="index.php?p=status-desconectado"><span class="fa fa-circle-o"></span> <?php echo $_TRA['Desconectado']; ?></a>
                   </li> 
                   <?php
					}
					if($StatusFalhado == 'S'){ 
				   ?>
                   <li>
                        <a href="index.php?p=status-falhado"><span class="fa fa-ban"></span> <?php echo $_TRA['Falhado']; ?></a>
                    </li>
                    <?php
					}
					if($StatusLogs == 'S'){ 
					?>
                    <li>
                        <a href="index.php?p=status-logs"><span class="fa fa-certificate"></span> <?php echo $_TRA['Logs']; ?></a>
                    </li>
                    <?php
					}
					if($StatusReshare == 'S'){ 
					?>
                    <li>
                        <a href="index.php?p=status-reshare"><span class="fa fa-dot-circle-o"></span> <?php echo $_TRA['Reshare']; ?></a>
                    </li>
                    <?php
					}
					?>
        			</ul>
                    </li>
                    <?php
					}
					
					if($OpcoesRelatorio == 'S'){
					echo "<li class=\"xn-title\">".$_TRA['relatorio']."</li>
					
					<li>
                        <a href=\"index.php?p=relatorio\"><span class=\"fa fa-file-text-o\"></span> <span class=\"xn-text\">".$_TRA['relatorio']."</span></a>
                    </li>
					";
					}
					
					
					if( ($ServidorcspVisualizar == 'S') || ($PerfilVisualizar == 'S') || ($ImagemperfilVisualizar == 'S') || ($EmailadicionarVisualizar == "S") || ($EmailModeloVisualizar == "S") || ($SMSadicionarVisualizar == "S") || ($SMSModeloVisualizar == "S") || ($TesteTempoVisualizar == "S") ){ 
						echo "<li class=\"xn-title\">".$_TRA['config']."</li>";
					}
					
					//Configurações
					if( ($ServidorcspVisualizar == 'S') || ($PerfilVisualizar == 'S') || ($ImagemperfilVisualizar == 'S') ){ 
					?>
                    
                    <li class="xn-openable">
                     <a href="#"><span class="fa fa-gears"></span> <span class="xn-text"><?php echo $_TRA['CSP']; ?></span></a>
                        <ul>   
                    <?php
					if($ServidorcspVisualizar == 'S'){ 
					?>    
                    <li>
                        <a href="index.php?p=csp"><span class="fa fa-gear"></span> <?php echo $_TRA['SCSP']; ?></a>
                    </li>
                    <?php
					}
					
					if($PerfilVisualizar == 'S'){ 
					?>
                    <li>
                        <a href="index.php?p=perfil"><span class="fa fa-bars"></span> <?php echo $_TRA['Perfil']; ?></a>
                    </li>
                    <?php
					}
					
					if($ImagemperfilVisualizar == 'S'){
					?>
					<li>
                        <a href="index.php?p=imagem-perfil"><span class="fa fa-picture-o"></span> <?php echo $_TRA['ImagemP']; ?></a>
                    </li>
                    <?php
					}
					?>
        			</ul>
                    </li>
                    <?php
					}
					
					if( ($EmailadicionarVisualizar == "S") || ($EmailModeloVisualizar == "S") ){
					?>
                    <li class="xn-openable">
                     <a href="#"><span class="fa fa-envelope-o"></span> <span class="xn-text"><?php echo $_TRA['email']; ?></span></a>
                    <ul>   
                    <?php
					if($EmailadicionarVisualizar == "S"){
					?>
					<li>
                        <a href="index.php?p=email-adicionar"><span class="fa fa-plus"></span> <?php echo $_TRA['Adicionar']; ?></a>
                    </li>
                    <?php
					}
					if($EmailModeloVisualizar == "S"){
					?>
                    <li>
                        <a href="index.php?p=email-modelo"><span class="fa fa-file-o"></span> <?php echo $_TRA['Modelo']; ?></a>
                    </li>
                    <?php
					}
					?>
        			</ul>
                    </li>
                    <?php
					}
					
					if( ($SMSadicionarVisualizar == "S") || ($SMSModeloVisualizar == "S") ){
					?>
                    <li class="xn-openable">
                     <a href="#"><span class="fa fa-mobile"></span> <span class="xn-text"><?php echo $_TRA['sms']; ?></span></a>
                    <ul>   
                    <?php
					if($SMSadicionarVisualizar == "S"){
					?>
					<li>
                        <a href="index.php?p=sms-adicionar"><span class="fa fa-plus"></span> <?php echo $_TRA['Adicionar']; ?></a>
                    </li>
                    <?php
					}
					if($SMSModeloVisualizar == "S"){
					?>
                    <li>
                        <a href="index.php?p=sms-modelo"><span class="fa fa-file-o"></span> <?php echo $_TRA['Modelo']; ?></a>
                    </li>
                    <?php
					}
					?>
        			</ul>
                    </li>
                    <?php
					}
					
					if($TesteTempoVisualizar == "S"){
					?>
                    <li>
                        <a href="index.php?p=tempo-teste"><span class="fa fa-clock-o"></span> <span class="xn-text"><?php echo $_TRA['tt']; ?></span></a>
                    </li>
                    <?php
					}
			
					if( ($OpcoesCircular == "S") || ($OpcoesMascaraURL == "S") || ($OpcoesExportar == 'S') || ($OpcoesImportar == 'S') || ($OpcoesVencimento == 'S') || ($OpcoesGrupoAcesso == 'S') || ($OpcoesLiberarComputador == "S") || ($OpcoesBackup == "S") || ($OpcoesEmailTemporario == "S") || ($AcessoUser == 1) ){ 
						echo "<li class=\"xn-title\">".$_TRA['opcoes']."</li>";
					}
					
					if($OpcoesCircular == "S"){
					?>
					<li>
                        <a class="pointer" onclick="EnviarCircular()"><span class="fa fa-envelope-o"></span> <span class="xn-text"><?php echo $_TRA['ec']; ?></span></a>
                    </li>
					<?php
					}
					
					if($OpcoesMascaraURL == "S"){
					?>
					<li>
                        <a href="index.php?p=mascara-perfil"><span class="fa fa-external-link"></span> <span class="xn-text"><?php echo $_TRA['mdp']; ?></span></a>
                    </li>
					<?php
					}
					
					if($OpcoesExportar == "S"){
					?>
                    <li>
                        <a href="index.php?p=exportar"><span class="fa fa-level-up"></span> <span class="xn-text"><?php echo $_TRA['Exportar']; ?></span></a>
                    </li>
                    <?php
					}
					
					if($OpcoesImportar == "S"){
					?>
                    <li>
                        <a href="index.php?p=importar"><span class="fa fa-level-down"></span> <span class="xn-text"><?php echo $_TRA['Importar']; ?></span></a>
                    </li>
                    <?php
					}
					
					if($OpcoesVencimento == "S"){
					?>
                    <li>
                        <a href="index.php?p=tempo-vencimento"><span class="fa fa-clock-o"></span> <span class="xn-text"><?php echo $_TRA['tp']; ?></span></a>
                    </li>
                    <?php
					}
					
					if($OpcoesGrupoAcesso == "S"){
					?>
                    <li>
                        <a href="index.php?p=grupo-de-acesso"><span class="fa fa-key"></span> <span class="xn-text"><?php echo $_TRA['gda']; ?></span></a>
                    </li>
                    <?php
					}
					
					if($OpcoesLiberarComputador == "S"){
					?>
                    <li>
                        <a href="index.php?p=liberar-computador"><span class="fa fa-desktop"></span> <span class="xn-text"><?php echo $_TRA['lb']; ?></span></a>
                    </li>
                    <?php
					}
					
					if($OpcoesBackup == "S"){
					?>
                    <li>
                        <a href="index.php?p=backup"><span class="fa fa-cloud-upload"></span> <span class="xn-text"><?php echo $_TRA['Backup']; ?></span></a>
                    </li>

                    <li>
                        <a href="index.php?p=backup-automatizado"><span class="fa fa-cloud-upload"></span> <span class="xn-text">Backup Automatizado</span></a>
                    </li>
					<?php
					}
					if($OpcoesEmailTemporario == "S"){
					?>
                    <li>
                        <a href="index.php?p=email-temporario"><span class="fa fa-times-circle"></span> <span class="xn-text"><?php echo $_TRA['etemp']; ?></span></a>
                    </li>
                    <?php
					}
					if($AcessoUser == 1){
					?>
					<li>
                        <a href="index.php?p=config-captcha"><span class="fa fa-retweet"></span> <span class="xn-text">Captcha</span></a>
                    </li>
                    
                   	<li>
                        <a href="index.php?p=email-teste"><span class="fa fa-envelope-o"></span> <span class="xn-text">E-mail Teste</span></a>
                    </li>
					<?php
					}
					?>
                    
                   	<li>
                        <a href="index.php?p=cupom"><span class="fa fa-tags"></span> <span class="xn-text">Cupom</span></a>
                    </li>
                    
                    <?php
					if( ($AcessoUser == 1) || ($AcessoUser == 2) ){
					?>
                    <li>
                        <a href="index.php?p=bit"><span class="fa fa-steam"></span> <span class="xn-text">Bit.ly</span></a>
                    </li>
                   	<?php
					}
					?>
                   
                   
                    
                    <li class="xn-title"><?php echo $_TRA['Suporte']; ?></li>
                    
                    <li>
                        <a class="pointer" onclick="EnviarComprovante();"><span class="fa fa-ticket"></span> <span class="xn-text"><?php echo $_TRA['ecompro']; ?></span></a>
                    </li>
                    
                    <li class="xn-openable">
                     <a href="#"><span class="fa fa-envelope"></span> <span class="xn-text"><?php echo $_TRA['Suporte']; ?></span></a>
                    <ul>   

					<li>
                        <a href="index.php?p=suporte&a=1"><span class="fa fa-inbox"></span> <?php echo $_TRA['cde']; ?></a>
                    </li>
       
                    <li>
                        <a href="index.php?p=suporte&a=2"><span class="fa fa-rocket"></span> <?php echo $_TRA['Enviados']; ?></a>
                    </li>
                    
                    <li>
                        <a href="index.php?p=suporte&a=3"><span class="fa fa-star"></span> <?php echo $_TRA['Estrela']; ?></a>
                    </li>
                    
                    <li>
                        <a href="index.php?p=suporte&a=4"><span class="fa fa-trash-o"></span> <?php echo $_TRA['Lixeira']; ?></a>
                    </li>

        			</ul>
                    </li>
							
                    <?php
					if( ($TemplateTema == "S") || ($TemplateInfo == "S") || ($TemplatePParede == "S") ){
					?>
                    
                    <li class="xn-title"><?php echo $_TRA['template']; ?></li>
          			
                    <?php
					if($TemplateTema == "S"){
					?>
					<li>
                        <a href="index.php?p=temas"><span class="fa fa-th-large"></span> <span class="xn-text"><?php echo $_TRA['temas']; ?></span></a>
                    </li>
                    <?php
					}
					
					if($TemplateInfo == "S"){
					?>
                    <li>
                        <a href="index.php?p=info"><span class="fa fa-info"></span> <span class="xn-text"><?php echo $_TRA['info']; ?></span></a>
                    </li>
                    <?php
					}
					
					if($TemplatePParede == "S"){
					?>
                    <li>
                        <a href="index.php?p=papel-de-parede"><span class="fa fa-picture-o"></span> <span class="xn-text"><?php echo $_TRA['papeldeparede']; ?></span></a>
                    </li>
                    <?php
					}
					}
					?>
        		
                 <li class="xn-title"><?php echo $_TRA['versao']." ".$VersaoPainel; ?></li>
                
                </ul>
                
               
                
                <!-- END X-NAVIGATION -->
            </div>
            
            <script type='text/javascript'>  
			
			function EnviarComprovante(){
				
				var comprovante = "S";
 				
				panel_refresh($(".page-container"));	
						
				$.post('ScriptModalSuporte.php', {comprovante: comprovante}, function(resposta) {
					
					setTimeout(panel_refresh($(".page-container")),500);
					
					$("#StatusGeral").html('');
					$("#StatusGeral").html(resposta);
				});
				
			}
			
			</script>
            
<?php
}else{
	echo Redirecionar('login.php');
}
?>