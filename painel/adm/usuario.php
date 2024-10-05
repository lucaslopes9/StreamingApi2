<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;

$ColunaRev = array('UserVisualizar', 'UserInfo', 'UserMensagem', 'UserBloquear', 'UserEditar', 'UserExcluir', 'UserAdicionar', 'UserLogin');
$VerificarAcesso = VerificarAcesso('user', $ColunaRev);

$AdminVisualizar = $VerificarAcesso[0];
$AdminInfo = $VerificarAcesso[1];
$AdminMensagem = $VerificarAcesso[2];
$AdminBloquear = $VerificarAcesso[3];
$AdminEditar = $VerificarAcesso[4];
$AdminExcluir = $VerificarAcesso[5];
$AdminAdicionar = $VerificarAcesso[6];
$UserLogin = $VerificarAcesso[7];

$ColunaRev2 = array('RevVisualizar');
$VerificarAcesso2 = VerificarAcesso('rev', $ColunaRev2);
$AdminVisualizar2 = $VerificarAcesso2[0];

if($AdminVisualizar == 'S'){
	
$status = empty($_GET['s']) ? 0 : $_GET['s'];
$user = empty($_GET['user']) ? 0 : $_GET['user'];

//Usuário
$CadUser = InfoUser(2);
$DataTablesPost = "usuario-processo";
$DataTablesTargets = "{\"targets\": 0,\"orderable\": false}, {\"targets\": 1,\"orderable\": false}, {\"targets\": 10,\"orderable\": false}";
	
$VerificarLimiteUser = VerificarLimiteUser($CadUser);
$VerificarCotaUser = VerificarCotaUser($CadUser);
$CotaUserDisponivel = $VerificarLimiteUser - $VerificarCotaUser;
?>

	<!-- START BREADCRUMB -->
                <ul class="breadcrumb">
                	<li><?php echo $_TRA['grupo']; ?></li>
                    <li class="active"><?php echo $_TRA['Usuario']; ?></li>
                </ul>
                <!-- END BREADCRUMB -->  
                
                <!-- PAGE TITLE -->
          <div class="page-title">                    
          <h2><span class="fa fa-user"></span> <?php echo $_TRA['Usuario']; ?></h2>
          </div>
                <!-- END PAGE TITLE -->   
 
                <!-- PAGE CONTENT WRAPPER -->
                <div class="page-content-wrap">                
                
                    <div class="row">
                        <div class="col-md-12">
                        
                        <div class="panel panel-default">
                                <div class="panel-heading">
                                <div class="row">
    <?php
	if( ($AdminAdicionar == 'S') && ($_SESSION['PrePago'] == "N") && ($CotaUserDisponivel > 0) || ($AdminAdicionar == 'S') && ($_SESSION['PrePago'] == "N") && ($VerificarLimiteUser == 0) || ($AdminAdicionar == 'S') && ($_SESSION['PrePago'] == "S") && ($_SESSION['Cota'] > 0) ){
	?>                       
    <div class="btn-group" style="padding:5px 0px 5px 0px;">
    <button type="button" class="Adicionar btn btn-info active"><?php echo $_TRA['Adicionar']; ?></button>
    &nbsp;&nbsp; 
    </div>  
    <?php
	}
	?> 
                 
    <div class="btn-group" style="padding:5px 0px 5px 0px;">
    <button type="button" class="btn btn-default"><span value="Todos" id="StatusUE"><?php echo $_TRA['Exibir']; ?></span></button>
    <button type="button" class="btn btn-default dropdown-toggle" data-toggle="dropdown" aria-expanded="false"><span class="caret"></span></button>
     <ul class="dropdown-menu" role="menu">
     <?php
     echo SelecionarExibirAll($CadUser);
	 ?>
     </ul>
     &nbsp;&nbsp; 
    </div>
    
    <div class="btn-group" style="padding:5px 0px 5px 0px;">
    <button type="button" class="btn btn-default"><span value="Todos" id="StatusE"><?php echo $_TRA['Status']; ?></span></button>
    <button type="button" class="btn btn-default dropdown-toggle" data-toggle="dropdown" aria-expanded="false"><span class="caret"></span></button>
     <ul class="dropdown-menu" role="menu">
     <li><a status="Todos" class="ExibirStatus pointer"><?php echo $_TRA['Todos']; ?></a></li>
     <li><a status="Ativos" class="ExibirStatus pointer"><?php echo $_TRA['Ativos']; ?></a></li>
     <li><a status="Bloqueados" class="ExibirStatus pointer"><?php echo $_TRA['Bloqueados']; ?></a></li>
     <li><a status="Esgotados" class="ExibirStatus pointer"><?php echo $_TRA['Esgotados']; ?></a></li>
     </ul>
     &nbsp;&nbsp; 
    </div>
    
    <div class="btn-group" style="padding:5px 0px 5px 0px;">
    <button type="button" class="btn btn-default"><span value="Todos" id="StatusP"><?php echo $_TRA['Perfil']; ?></span></button>
    <button type="button" class="btn btn-default dropdown-toggle" data-toggle="dropdown" aria-expanded="false"><span class="caret"></span></button>
     <ul class="dropdown-menu" role="menu">
     <?php echo PerfilSelect($CadUser); ?>
     </ul>
     &nbsp;&nbsp; 
    </div>
    
    <div class="ExibirAllOpcoes btn-group" style="padding:5px 0px 5px 0px;"></div>
    </div> 
    
    <div class="row">                            
    <div class="btn-group col-md-3" style="padding:5px 0px 5px 0px;">    
                          
    <div class="input-group date">
    	<input type="text" id="PesquisaEntreData" name="PesquisaEntreData" class="form-control"/>
        <span class="input-group-addon"><span class="glyphicon glyphicon-calendar"></span></span>
    </div>
	</div>
    
    <div class="btn-group" style="padding:5px 0px 5px 5px;">                         
    <button type="button" class="ExibirPorData btn btn-success">Exibir por Data</button>
    </div>
    </div>                             

                                    <ul class="panel-controls">
                                        <li><a href="#" class="panel-fullscreen"><span class="fa fa-expand"></span></a></li>
                                        <li class="dropdown">
                                            <a href="#" class="dropdown-toggle" data-toggle="dropdown" aria-expanded="false"><span class="fa fa-cog"></span></a>                                            
                                            <ul class="dropdown-menu">
                                                <li><a href="#" class="panel-collapse"><span class="fa fa-angle-down"></span> <?php echo $_TRA['esconder']; ?></a></li>
                                                <li><a href="#" class="panel-refresh"><span class="fa fa-refresh"></span> <?php echo $_TRA['atualizar']; ?></a></li>
                                            </ul>                                        
                                        </li>
                                    </ul>
                                </div>
                                <div class="panel-body">
                                                                
                                    <div class="table-responsive">
                               <table id="Tabela" class="table datatable">
                               <thead>
                               		<tr>
                                    	<th width="5"><input type="checkbox" name="TotalAll" id="TotalAll" class="MarcarAll" OnClick="marcardesmarcar();"></th>
                                    	<th><?php echo $_TRA['foto']; ?></th>
                                        <th><?php echo $_TRA['nome']; ?></th>
                                        <th><?php echo $_TRA['user']; ?></th>
                                        <th><?php echo $_TRA['Senha']; ?></th>
                                        <th><?php echo $_TRA['email']; ?></th>
                                        <th><?php echo $_TRA['Perfil']; ?></th>
                                        <th><?php echo $_TRA['conexao']; ?></th>
                                        <th><?php echo $_TRA['DataPremio']; ?></th>
                                        <th><?php echo $_TRA['cpor']; ?></th>
                                        <?php
										if( ($AdminInfo == 'S') || ($AdminMensagem == 'S') || ($AdminBloquear == 'S') || ($AdminEditar == 'S') || ($AdminExcluir == 'S') || ($AdminVisualizar2 == 'S') ){
                                        echo "<th>".$_TRA['opcoes']."</th>";
										}
										?>
                                    </tr>
                                </thead>
                                <tbody>
                               	<tr style="height: auto;"></tr>
                                </tbody>
                                        </table>
                                    </div>
                                </div>                             
                            </div>



                        </div>
                    </div>                                
                    
                </div>
                <!-- PAGE CONTENT WRAPPER -->      
        
    

		<div id="StatusGeral"></div>        
<!-- START SCRIPTS -->
        <!-- START PLUGINS -->
        <script type="text/javascript" src="js/plugins/jquery/jquery.min.js"></script>
        <script type="text/javascript" src="js/plugins/jquery/jquery-ui.min.js"></script>
        <script type="text/javascript" src="js/plugins/bootstrap/bootstrap.min.js"></script>  
        <!-- END PLUGINS -->
        
        <script type="text/javascript" src="js/moment.min.js"></script>
        
        <script type="text/javascript" src="js/daterangepicker.js"></script>
        <link rel="stylesheet" type="text/css" href="css/daterangepicker.css" />

        <!-- START THIS PAGE PLUGINS-->        
        <script type='text/javascript' src='js/plugins/icheck/icheck.min.js'></script>
        <script type="text/javascript" src="js/plugins/mcustomscrollbar/jquery.mCustomScrollbar.min.js"></script>  
        <script type='text/javascript' src='js/plugins/maskedinput/jquery.maskedinput.min.js'></script>  
        <script type="text/javascript" src="js/plugins/datatables/jquery.dataTables.min.js"></script>
        <!-- END THIS PAGE PLUGINS-->        

        <!-- START TEMPLATE -->
        <?php include_once("js/settings".Idioma(2).".php"); ?>
        <script type="text/javascript" src="js/plugins.js"></script>        
        <script type="text/javascript" src="js/actions.js"></script>
        <!-- END TEMPLATE -->
        
        <?php 
		
		if(empty($status)){
			include_once("js/DataTablesPost".Idioma(2).".php");
		}
		else{
		?>
        <script type="text/javascript" src="js/DataTables<?php echo Idioma(2); ?>.js"></script>  
        <?php
		}
		
		?>
                
        <script type='text/javascript'> 
			
		$(function() {
			$('input[name="PesquisaEntreData"]').daterangepicker({
				locale: {
      				format: 'DD/MM/YYYY'
    			}
			});
		});
		
		<?php
		if($UserLogin == 'S'){
		?>
		
		function AlterarLogin(usuario){ 
		
				panel_refresh($(".page-container"));
		
				$.post('ScriptModalAlterarLoginUser.php', {usuario: usuario}, function(resposta) {
					
				setTimeout(panel_refresh($(".page-container")),500);
					
				$("#StatusGeral").html('');
				$("#StatusGeral").html(resposta);
				});
		}
		
		<?php
		}
		?>
		
		function SMSUser(usuario){
			
				panel_refresh($(".page-container"));
			
				$.post('ScriptModalEnviarSMSUsuario.php', {usuario: usuario}, function(resposta) {
					
				setTimeout(panel_refresh($(".page-container")),500);
					
				$("#StatusGeral").html('');
				$("#StatusGeral").html(resposta);
				});
		}
		
		<?php
		if( ($_SESSION['PrePago'] == "S") && ($_SESSION['Cota'] > 0) ){
		?>
		function RenovarUser(usuario){
 		
 				var titulo = '<?php echo $_TRA['ru']; ?>?';
				var texto = '<?php echo $_TRA['tcqdru']; ?> '+usuario+'?';
				var tipo = 'success';
				var url = 'EnviarRenovarUsuario';
				var fa = 'fa fa-refresh';  
			
				$.post('ScriptAlertaJS.php', {id: usuario, titulo: titulo, texto: texto, tipo: tipo, url: url, fa: fa}, function(resposta) {
				$("#StatusGeral").html('');
				$("#StatusGeral").html(resposta);
				});
				
		}
		<?php
		}
		else{
		?>
		
		function RenovarUserNormal(usuario){
 		
 				var titulo = '<?php echo $_TRA['ru']; ?>?';
				var texto = '<?php echo $_TRA['tcqdru']; ?> '+usuario+'?';
				var tipo = 'success';
				var url = 'EnviarRenovarUsuarioNormal';
				var fa = 'fa fa-refresh';  
			
				$.post('ScriptAlertaJS.php', {id: usuario, titulo: titulo, texto: texto, tipo: tipo, url: url, fa: fa}, function(resposta) {
				$("#StatusGeral").html('');
				$("#StatusGeral").html(resposta);
				});
				
		}
			
		<?php
		}
		?>
		
		function XMLUserRem(usuario, status){
			
				panel_refresh($(".page-container"));
 		
				$.post('EnviarUserRemXml.php', {usuario: usuario}, function(resposta) {
					
					setTimeout(panel_refresh($(".page-container")),500);
					
					$("#"+status+"").html('');
					$("#"+status+"").html(resposta);
				});
				
		}
        
        function XMLUserAdd(usuario, status){
			
				panel_refresh($(".page-container"));
			
				$.post('EnviarUserAddXml.php', {usuario: usuario}, function(resposta) {
					
					setTimeout(panel_refresh($(".page-container")),500);
					
					$("#"+status+"").html('');
					$("#"+status+"").html(resposta);
				});
				
		}
		
		<?php
		if($AdminVisualizar2 == 'S'){
		?>
		
		function RevendedorUser(usuario){
 		
 				var titulo = '<?php echo $_TRA['tr']; ?>?';
				var texto = '<?php echo $_TRA['tcqdtour']; ?> '+usuario+'?';
				var tipo = 'danger';
				var url = 'EnviarTornarRevUser';
				var fa = 'fa fa-users';  
			
				$.post('ScriptAlertaJS.php', {id: usuario, titulo: titulo, texto: texto, tipo: tipo, url: url, fa: fa}, function(resposta) {
				$("#StatusGeral").html('');
				$("#StatusGeral").html(resposta);
				});
				
		}
		
 		<?php
		}
 		if($AdminExcluir == 'S'){
		?>
 			function DeletarUser(usuario){
 		
 				var titulo = '<?php echo $_TRA['excluir']; ?>?';
				var texto = '<?php echo $_TRA['tcqdea']; ?> '+usuario+'?';
				var tipo = 'danger';
				var url = 'EnviarDeletarUser';
				var fa = 'fa fa-trash-o';  
			
				$.post('ScriptAlertaJS.php', {id: usuario, titulo: titulo, texto: texto, tipo: tipo, url: url, fa: fa}, function(resposta) {
				$("#StatusGeral").html('');
				$("#StatusGeral").html(resposta);
				});
				
			}
		<?php
		}
		if($AdminBloquear == 'S'){
		?>
		
		function BloquearUser(usuario){ 
 		
 				var titulo = '<?php echo $_TRA['bloquear']; ?>?';
				var texto = '<?php echo $_TRA['tcqdba']; ?> '+usuario+'?';
				var tipo = 'danger';
				var url = 'EnviarBloquearUser';
				var fa = 'fa fa-lock';  
			
				$.post('ScriptAlertaJS.php', {id: usuario, titulo: titulo, texto: texto, tipo: tipo, url: url, fa: fa}, function(resposta) {
				$("#StatusGeral").html('');
				$("#StatusGeral").html(resposta);
				});
				
		}
		
		function DesbloquearUser(usuario){ 
 		
 				var titulo = '<?php echo $_TRA['desbloquear']; ?>?';
				var texto = '<?php echo $_TRA['tcqdda']; ?> '+usuario+'?';
				var tipo = 'danger';
				var url = 'EnviarDesbloquearUser';
				var fa = 'fa fa-unlock-alt';  
			
				$.post('ScriptAlertaJS.php', {id: usuario, titulo: titulo, texto: texto, tipo: tipo, url: url, fa: fa}, function(resposta) {
				$("#StatusGeral").html('');
				$("#StatusGeral").html(resposta);
				});
				
		}
		
		<?php
		}
		
		if($AdminEditar == 'S'){
		?>
		
		function EditarUser(usuario){ 
		
				panel_refresh($(".page-container"));
		
				$.post('ScriptModalUserEditar.php', {usuario: usuario}, function(resposta) {
					
				setTimeout(panel_refresh($(".page-container")),500);
					
				$("#StatusGeral").html('');
				$("#StatusGeral").html(resposta);
				});
		}
		
		<?php
		}
		
		if( ($AdminAdicionar == 'S') && ($_SESSION['PrePago'] == "N") && ($CotaUserDisponivel > 0) || ($AdminAdicionar == 'S') && ($_SESSION['PrePago'] == "N") && ($VerificarLimiteUser == 0) || ($AdminAdicionar == 'S') && ($_SESSION['PrePago'] == "S") && ($_SESSION['Cota'] > 0) ){
		?>
		
		$(function(){  
 			$("button.Adicionar").click(function() { 
			
				panel_refresh($(".page-container"));
 						
				$.post('ScriptModalUserAdicionar.php', function(resposta) {
					
				setTimeout(panel_refresh($(".page-container")),500);
					
				$("#StatusGeral").html('');
				$("#StatusGeral").html(resposta);
				});
				
			});
		});
		<?php
		}
		?>
			
		$(function(){  
 			$("button.ExibirPorData").click(function() {
				
				var PesquisaEntreData = $('.input-group input[name="PesquisaEntreData"]').val();
				var usuario = $('#StatusUE').attr('value');
								
				if(status == 'Todos'){
					usuarioE = '<?php echo $_TRA['Todos']; ?>';
				}
				else{
					usuarioE = usuario;
				}
				
				$("#StatusUE").html(usuarioE);

				$("#StatusUE").attr('value', usuario);
				
				var status = $('#StatusE').attr('value');
				var perfil = $('#StatusP').attr('value');
					
				var panel = $('.PanelStatus');
       		    panel_refresh(panel);
		
				$.post('usuario-status-entre-datas.php', {usuario: usuario, status: status, perfil: perfil, PesquisaEntreData: PesquisaEntreData}, function(resposta) {
					
					setTimeout(function(){
            			panel_refresh(panel);
        			},500);	

					$(".table-responsive").html('');
				    $(".table-responsive").html(resposta);
					
				});
			});
		});
		
		$(function(){  
 			$("a.Exibir").click(function() { 
				$(".ExibirAllOpcoes").html('');
 			
				var usuario = $(this).attr("usuario"); 
				
				if(status == 'Todos'){
					usuarioE = '<?php echo $_TRA['Todos']; ?>';
				}
				else{
					usuarioE = usuario;
				}
				
				$("#StatusUE").html(usuarioE);

				$("#StatusUE").attr('value', usuario);
				
				var status = $('#StatusE').attr('value');
				var perfil = $('#StatusP').attr('value');
				
				$.post('usuario-status.php', {usuario: usuario, status: status, perfil: perfil}, function(resposta) {
					
				$(".table-responsive").html('');
				$(".table-responsive").html(resposta);
				});
				
				
			});
		});
		
		$(function(){  
 			$("a.ExibirStatus").click(function() { 
 				$(".ExibirAllOpcoes").html('');
				
				var status = $(this).attr("status"); 
				
				if(status == 'Todos'){
					statusE = '<?php echo $_TRA['Todos']; ?>';
				}
				else if(status == 'Ativos'){
					statusE = '<?php echo $_TRA['Ativos']; ?>';
				}
				else if(status == 'Bloqueados'){
					statusE = '<?php echo $_TRA['Bloqueados']; ?>';
				}
				else if(status == 'Esgotados'){
					statusE = '<?php echo $_TRA['Esgotados']; ?>';
				}
				else{
					statusE = '<?php echo $_TRA['Todos']; ?>';
				}
				
				$("#StatusE").html(statusE);
				$("#StatusE").attr('value', status);
				
				var usuario = $('#StatusUE').attr('value');
				var perfil = $('#StatusP').attr('value');
				
				$.post('usuario-status.php', {usuario: usuario, status: status, perfil: perfil}, function(resposta) {
					
				$(".table-responsive").html('');
				$(".table-responsive").html(resposta);
				});
								
			});
		});
		
		
		$(function(){  
 			$("a.ExibirPerfil").click(function() { 
 				$(".ExibirAllOpcoes").html('');
				
				var perfil = $(this).attr("perfil"); 
				var nome = $(this).attr("nome"); 
				
				$("#StatusP").html(nome);
				$("#StatusP").attr('value', perfil);
				
				var usuario = $('#StatusUE').attr('value');
				var status = $('#StatusE').attr('value');
								
				$.post('usuario-status.php', {usuario: usuario, status: status, perfil: perfil}, function(resposta) {

				$(".table-responsive").html('');
				$(".table-responsive").html(resposta);
				});
								
			});
		});
		
		function marcardesmarcar(){
		
		TotalAll = $('[name="TotalAll"]:checked').length;		
		TotalSUser = $('[name="SelectUser[]"]:checked').length;
		TotalSGeral = $('[name="SelectUser[]"]').length;
		
 		$('.MarcarTodos').each(
        function(){
				if ( (TotalAll > 0) && (TotalSUser == 0) ){
					$(this).prop("checked", true);
				}
           		else if ( (TotalAll == 0) && (TotalSUser == TotalSGeral) ){
           			$(this).prop("checked", false);  
				}
				else if ( (TotalAll > 0) && (TotalSUser > 0) ){
					$(this).prop("checked", true);
				}
				else if ( (TotalAll == 0) && (TotalSGeral != TotalSUser) ){
					$(this).prop("checked", false); 
				}
           		else {
				$(this).prop("checked", false);   
				}
         		}
   		);
				VerificarCheck();		 
		}
		
		function VerificarCheck(){
		
		TotalSUser = $('[name="SelectUser[]"]:checked').length;
		TotalSGeral = $('[name="SelectUser[]"]').length;
		
		if(TotalSUser == TotalSGeral){
			$(".MarcarAll").prop("checked", true);
		}
		
		if( TotalSUser > 0){
			$.post('SelecionarOpcoesUser.php', function(resposta) {
				$(".ExibirAllOpcoes").html(resposta);
			});
		}
		else{
			$(".ExibirAllOpcoes").html(''); 
			$(".MarcarAll").prop("checked", false);
		}
		}
		
		<?php
		if($AdminInfo == 'S'){
		?>
		
		function InfoUser(usuario){
			
				panel_refresh($(".page-container"));
 						
				$.post('ScriptModalInfoUser.php', {usuario: usuario}, function(resposta) {
					
				setTimeout(panel_refresh($(".page-container")),500);
					
				$("#StatusGeral").html('');
				$("#StatusGeral").html(resposta);
				});
		}
		
		<?php
		}
		if($AdminMensagem == 'S'){
		?>
		
		function MensagemUser(usuario){
			
				panel_refresh($(".page-container"));
			
				$.post('ScriptModalEnviarMensagemUser.php', {usuario: usuario}, function(resposta) {
					
				setTimeout(panel_refresh($(".page-container")),500);
					
				$("#StatusGeral").html('');
				$("#StatusGeral").html(resposta);
				});
		}
		
		<?php	
		}
		?>
		
 		function AbrirStatus(id){
 				$(".ExibirAllOpcoes").html('');
				
				if(id == 1){
					var status = 'Ativos';
					statusE = '<?php echo $_TRA['Ativos']; ?>';
				}
				else if(id == 2){
					var status = 'Esgotados';
					statusE = '<?php echo $_TRA['Esgotados']; ?>';
				}
				else if(id == 3){
					var status = 'Bloqueados';
					statusE = '<?php echo $_TRA['Bloqueados']; ?>';
				}
				
				$("#StatusE").html(statusE);
				$("#StatusE").attr('value', status);
				
				var usuario = $('#StatusUE').attr('value');
				var perfil = $('#StatusP').attr('value');
				
				$.post('usuario-status.php', {usuario: usuario, status: status, perfil: perfil}, function(resposta) {
					
				$(".table-responsive").html('');
				$(".table-responsive").html(resposta);
				});
		}
		
		function AbrirUser(usuario){
			$.post('usuario-status-user.php', {usuario: usuario}, function(resposta) {
				$(".table-responsive").html('');
				$(".table-responsive").html(resposta);
			});
		}
			
		<?php
		if(!empty($user)){
		?>
			AbrirUser('<?php echo $user; ?>');
		<?php
		}
		elseif($status == 1){
		?>
			AbrirStatus(1);
		<?php
		}
		elseif($status == 2){
		?>
			AbrirStatus(2);
		<?php
		}
		elseif($status == 3){
		?>
			AbrirStatus(3);
		<?php
		}
		?>
		
		
		</script>
          

    <!-- END SCRIPTS -->    
<?php
}else{
	echo Redirecionar('index.php');
}
}else{
	echo Redirecionar('login.php');
}	
?>