<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;

$ColunaAdmin = array('AdminVisualizar', 'AdminAcesso', 'AdminInfo', 'AdminMensagem', 'AdminBloquear', 'AdminDesativar', 'AdminEditar', 'AdminExcluir', 'AdminAdicionar', 'AdminLogin');
$VerificarAcesso = VerificarAcesso('admin', $ColunaAdmin);

$AdminVisualizar = $VerificarAcesso[0];
$AdminAcesso = $VerificarAcesso[1];
$AdminInfo = $VerificarAcesso[2];
$AdminMensagem = $VerificarAcesso[3];
$AdminBloquear = $VerificarAcesso[4];
$AdminDesativar = $VerificarAcesso[5];
$AdminEditar = $VerificarAcesso[6];
$AdminExcluir = $VerificarAcesso[7];
$AdminAdicionar = $VerificarAcesso[8];
$AdminLogin = $VerificarAcesso[9];
 
if($AdminVisualizar == 'S'){
	
$user = empty($_GET['user']) ? 0 : $_GET['user'];

//Usuário
$CadUser = InfoUser(2);

$SQLUser = "SELECT id, nome, usuario, senha, email, foto, perfil, bloqueado, inativo, celular FROM admin WHERE CadUser = :CadUser";
$SQLUser = $painel_user->prepare($SQLUser);
$SQLUser->bindParam(':CadUser', $CadUser, PDO::PARAM_STR);
$SQLUser->execute();
?>

	<!-- START BREADCRUMB -->
                <ul class="breadcrumb">
                	<li><?php echo $_TRA['grupo']; ?></li>
                    <li class="active"><?php echo $_TRA['admin']; ?></li>
                </ul>
                <!-- END BREADCRUMB -->  
                
                <!-- PAGE TITLE -->
          <div class="page-title">                    
          <h2><span class="fa fa-user"></span> <?php echo $_TRA['admin']; ?></h2>
          </div>
                <!-- END PAGE TITLE -->   
 
                <!-- PAGE CONTENT WRAPPER -->
                <div class="page-content-wrap">                
                
                    <div class="row">
                        <div class="col-md-12">
                        
                        <div class="panel panel-default">
                                <div class="panel-heading">
    <?php
	if($AdminAdicionar == 'S'){
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
     echo SelecionarExibirAdmin($CadUser);
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
     <li><a status="Inativos" class="ExibirStatus pointer"><?php echo $_TRA['Inativos']; ?></a></li>
     </ul>
     &nbsp;&nbsp; 
    </div>
    
    <div class="ExibirAllOpcoes btn-group" style="padding:5px 0px 5px 0px;"></div>

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
                                        <th><?php echo $_TRA['cpor']; ?></th>
                                        <?php
										if( ($AdminAcesso == 'S') || ($AdminInfo == 'S') || ($AdminMensagem == 'S') || ($AdminBloquear == 'S') || ($AdminDesativar == 'S') || ($AdminEditar == 'S') || ($AdminExcluir == 'S') ){
                                        echo "<th>".$_TRA['opcoes']."</th>";
										}
										?>
                                    </tr>
                                </thead>
                                <tbody>
     
                                
                                        <?php
										while($LnUser = $SQLUser->fetch()){
											
										if($LnUser['bloqueado'] == "S"){
										$status = "&nbsp;&nbsp;<span class=\"pointer label label-danger\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$_TRA['Bloqueado']."\">".$_TRA['Bloqueado'][0]."</span>";
										}else{
										$status = "&nbsp;&nbsp;<span class=\"pointer label label-success\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$_TRA['desbloqueado']."\">".$_TRA['desbloqueado'][0]."</span>";
										}
										
										if($LnUser['inativo'] == "S"){
										$statusA = "&nbsp;&nbsp;<span class=\"pointer label label-danger\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$_TRA['Desativado']."\">".$_TRA['Desativado'][0]."</span>";
										}else{
										$statusA = "&nbsp;&nbsp;<span class=\"pointer label label-success\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$_TRA['Ativado']."\">".$_TRA['Ativado'][0]."</span>";
										}
											
										$ICheckbox = ($CadUser == $LnUser['usuario']) ? "<input type=\"checkbox\" disabled>" : "<input type=\"checkbox\" class=\"MarcarTodos\" name=\"SelectUser[]\" id=\"SelectUser\" value=\"".$LnUser['usuario']."\" Onclick=\"VerificarCheck()\">";
																																								
										if(empty($LnUser['perfil'])){
											$perfil = "";
										}
										else{
											$perfil = SelecionarPerfil($LnUser['perfil']);
										}
											
										$Foto = Foto($LnUser['foto']);
										echo "
                                        <tr>
											<td width=\"5\">".$ICheckbox."</td>
											<td><img class=\"pointer\" src=\"".$Foto."\" alt=\"".$LnUser['nome']."\" height=\"32\" width=\"32\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$LnUser['nome']."\"></td>
                                        	<td>".$LnUser['nome'].$status.$statusA."</td>
                                        	<td>".$LnUser['usuario']."</td>
                                        	<td>".$LnUser['senha']."</td>";
											
											if(!empty($LnUser['email'])){
                                        	echo "<td><span style=\"display: none;\">".$LnUser['email']."</span><span class=\"pointer label label-success\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$LnUser['email']."\"><i class=\"fa fa-at\"></i></span></td>";
											}
											else{
											echo "<td><span class=\"pointer label label-danger\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$_TRA['eunpede']."\"><i class=\"fa fa-at\"></i></span></td>";
											}
											
											echo "<td><div class=\"form-group\"><span style=\"display: none;\">".$LnUser['perfil']."</span>".$perfil."</div></td>
											<td>".$CadUser."</td>";
											
									if( ($AdminAcesso == 'S') || ($AdminInfo == 'S') || ($AdminMensagem == 'S') || ($AdminBloquear == 'S') || ($AdminDesativar == 'S') || ($AdminEditar == 'S') || ($AdminExcluir == 'S') ){		
                                    echo "<td><div class=\"form-group\">";
									
									if( ($CadUser != $LnUser['usuario']) && ($AdminLogin == 'S')){
									echo "<a Onclick=\"AlterarLogin('".$LnUser['usuario']."')\" class=\"label label-primary\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$_TRA['au']."\"><i class=\"fa fa-edit\"></i></a>&nbsp;";
									}
										
									if( ($CadUser != $LnUser['usuario']) && ($AdminAcesso == 'S')){
									echo "<a Onclick=\"AcessoUser('".$LnUser['usuario']."')\" class=\"label label-warning\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$_TRA['Acesso']."\"><i class=\"fa fa-key\"></i></a>&nbsp;";
									}
									
									if($AdminInfo == 'S'){
									echo "<a Onclick=\"InfoUser('".$LnUser['usuario']."')\" class=\"label label-info\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$_TRA['info']."\"><i class=\"fa fa-info-circle\"></i></a>&nbsp;";
									}
									
									if( ($CadUser != $LnUser['usuario']) && ($AdminMensagem == 'S') && !empty($LnUser['email']) ){
									echo "<a Onclick=\"MensagemUser('".$LnUser['usuario']."')\" class=\"label label-primary\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$_TRA['em']."\"><i class=\"fa fa-envelope-o\"></i></a>&nbsp;";
									}
									
									if( ($CadUser != $LnUser['usuario']) && !empty($LnUser['celular']) ){
									echo "<a class=\"label label-success\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$_TRA['EnviarSMS']."\" Onclick=\"SMSUser('".$LnUser['usuario']."')\"><i class=\"fa fa-mobile\"></i></a>&nbsp;";
									}
									
									if( ($CadUser != $LnUser['usuario']) && ($AdminBloquear == 'S') ){
									if($LnUser['bloqueado'] == "S"){
									echo "<a Onclick=\"DesbloquearUser('".$LnUser['usuario']."')\" class=\"label label-success\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$_TRA['desbloquear']."\"><i class=\"fa fa-unlock-alt\"></i></a>&nbsp;";
									}else{
									echo "<a Onclick=\"BloquearUser('".$LnUser['usuario']."')\" class=\"label label-danger\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$_TRA['bloquear']."\"><i class=\"fa fa-lock\"></i></a>&nbsp;";
									}
									}
									
									if( ($CadUser != $LnUser['usuario']) && ($AdminDesativar == 'S') ){
									if($LnUser['inativo'] == "S"){
									echo "<a Onclick=\"AtivarUser('".$LnUser['usuario']."')\" class=\"label label-success\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$_TRA['ativar']."\"><i class=\"fa fa-check\"></i></a>&nbsp;";
									}else{
									echo "<a Onclick=\"DesativarUser('".$LnUser['usuario']."')\" class=\"label label-danger\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$_TRA['desativar']."\"><i class=\"fa fa-times\"></i></a>&nbsp;";
									}
									}
									
									if($AdminEditar == 'S'){
									echo "<a Onclick=\"EditarUser('".$LnUser['usuario']."')\" class=\"label label-warning\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$_TRA['editar']."\"><i class=\"fa fa-pencil\"></i></a>&nbsp;";
									}
									
									if( ($CadUser != $LnUser['usuario']) && ($AdminExcluir == 'S') ){
									echo "<a Onclick=\"DeletarUser('".$LnUser['usuario']."')\" class=\"label label-danger\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$_TRA['excluir']."\"><i class=\"fa fa-trash-o\"></i></a>&nbsp;";
									}
											
									echo "</div>
											
											</td>";
									}
											
									echo "</tr>";
										}
										?>
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

        <!-- START THIS PAGE PLUGINS-->        
        <script type='text/javascript' src='js/plugins/icheck/icheck.min.js'></script>
        <script type="text/javascript" src="js/plugins/mcustomscrollbar/jquery.mCustomScrollbar.min.js"></script>  
        <script type='text/javascript' src='js/plugins/maskedinput/jquery.maskedinput.min.js'></script>  
                <script type="text/javascript" src="js/plugins/datatables/jquery.dataTables.min.js"></script>
        <script type="text/javascript" src="js/DataTables<?php echo Idioma(2); ?>.js"></script>  
        
        <!-- END THIS PAGE PLUGINS-->        

        <!-- START TEMPLATE -->
        <?php include_once("js/settings".Idioma(2).".php"); ?>
        <script type="text/javascript" src="js/plugins.js"></script>        
        <script type="text/javascript" src="js/actions.js"></script>
        <!-- END TEMPLATE -->
        
        <script type='text/javascript'>  
		
		<?php
		if($AdminLogin == 'S'){
		?>
		
		function AlterarLogin(usuario){ 
		
				panel_refresh($(".page-container"));
		
				$.post('ScriptModalAlterarLoginAdmin.php', {usuario: usuario}, function(resposta) {
					
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
			
				$.post('ScriptModalEnviarSMSAdmin.php', {usuario: usuario}, function(resposta) {
					
				setTimeout(panel_refresh($(".page-container")),500);
					
				$("#StatusGeral").html('');
				$("#StatusGeral").html(resposta);
				});
		}
		
 		<?php
 		if($AdminExcluir == 'S'){
		?>
		function DeletarUser(usuario){
 		
 				var titulo = '<?php echo $_TRA['excluir']; ?>?';
				var texto = '<?php echo $_TRA['tcqdea']; ?> '+usuario+'?';
				var tipo = 'danger';
				var url = 'EnviarDeletarAdmin';
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
				var url = 'EnviarBloquearAdmin';
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
				var url = 'EnviarDesbloquearAdmin';
				var fa = 'fa fa-unlock-alt';  
			
				$.post('ScriptAlertaJS.php', {id: usuario, titulo: titulo, texto: texto, tipo: tipo, url: url, fa: fa}, function(resposta) {
				$("#StatusGeral").html('');
				$("#StatusGeral").html(resposta);
				});
				
		}
		
		<?php
		}
		
		if($AdminDesativar == 'S'){
		?>
		
		function DesativarUser(usuario){ 
 		
 				var titulo = '<?php echo $_TRA['desativar']; ?>?';
				var texto = '<?php echo $_TRA['tcqdd1a']; ?> '+usuario+'?';
				var tipo = 'danger';
				var url = 'EnviarDesativarAdmin';
				var fa = 'fa fa-times';  
			
				$.post('ScriptAlertaJS.php', {id: usuario, titulo: titulo, texto: texto, tipo: tipo, url: url, fa: fa}, function(resposta) {
				$("#StatusGeral").html('');
				$("#StatusGeral").html(resposta);
				});
				
		}
		
		function AtivarUser(usuario){ 
 		
 				var titulo = '<?php echo $_TRA['ativar']; ?>?';
				var texto = '<?php echo $_TRA['tcqda1a']; ?> '+usuario+'?';
				var tipo = 'danger';
				var url = 'EnviarAtivarAdmin';
				var fa = 'fa fa-check';  
			
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
		
				$.post('ScriptModalAdmin.php', {usuario: usuario}, function(resposta) {
					
				setTimeout(panel_refresh($(".page-container")),500);
					
				$("#StatusGeral").html('');
				$("#StatusGeral").html(resposta);
				});
		}
		
		<?php
		}
		
		if($AdminAdicionar == 'S'){
		?>
		
		$(function(){  
 			$("button.Adicionar").click(function() { 
			
				panel_refresh($(".page-container"));
 						
				$.post('ScriptModalAdminAdicionar.php', function(resposta) {
					
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
				
				var panel = $(this).parents(".panel");
       		    panel_refresh(panel);

				$.post('administrador-status.php', {usuario: usuario, status: status}, function(resposta) {
				
				setTimeout(function(){
            	panel_refresh(panel);
        		},500);	
					
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
				else if(status == 'Inativos'){
					statusE = '<?php echo $_TRA['Inativos']; ?>';
				}
				else{
					statusE = '<?php echo $_TRA['Todos']; ?>';
				}
				
				$("#StatusE").html(statusE);
				$("#StatusE").attr('value', status);
				
				var usuario = $('#StatusUE').attr('value');
				
				var panel = $(this).parents(".panel");
       		    panel_refresh(panel);

				$.post('administrador-status.php', {usuario: usuario, status: status}, function(resposta) {
				
				setTimeout(function(){
            	panel_refresh(panel);
        		},500);	
					
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
			$.post('SelecionarOpcoes.php', function(resposta) {
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
 						
				$.post('ScriptModalInfoAdmin.php', {usuario: usuario}, function(resposta) {
					
				setTimeout(panel_refresh($(".page-container")),500);
					
				$("#StatusGeral").html('');
				$("#StatusGeral").html(resposta);
				});
		}
		
		
		<?php
		}
		
		if($AdminAcesso == 'S'){
		?>
		
		function AcessoUser(usuario){
			
				panel_refresh($(".page-container"));
			
				$.post('ScriptModalAcessos.php', {usuario: usuario}, function(resposta) {
					
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
			
				$.post('ScriptModalEnviarMensagem.php', {usuario: usuario}, function(resposta) {
					
				setTimeout(panel_refresh($(".page-container")),500);
					
				$("#StatusGeral").html('');
				$("#StatusGeral").html(resposta);
				});
		}
				
		<?php	
		}
		?>
			
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