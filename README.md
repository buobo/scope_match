<!-- wp:paragraph -->
<p>项目地址：<a href="https://github.com/buobo/scope_match">https://github.com/buobo/scope_match</a></p>
<!-- /wp:paragraph -->

<!-- wp:heading -->
<h2 class="wp-block-heading">插件简介</h2>
<!-- /wp:heading -->

<!-- wp:paragraph -->
<p><code>scope_match</code> 是一个用于 IDA 9.0 Hex-Rays 伪代码视图的辅助阅读插件。</p>
<!-- /wp:paragraph -->

<!-- wp:paragraph -->
<p>它可以在伪代码窗口顶部显示当前代码所在的多层作用域，帮助用户快速判断当前代码属于哪个 <code>if</code>、<code>else</code>、<code>for</code>、<code>while</code>、<code>switch</code> 或函数代码块。</p>
<!-- /wp:paragraph -->

<!-- wp:paragraph -->
<p>插件适合用于阅读较长、嵌套较深、逻辑分支复杂的反编译伪代码。</p>
<!-- /wp:paragraph -->

<!-- wp:heading -->
<h2 class="wp-block-heading">主要功能</h2>
<!-- /wp:heading -->

<!-- wp:heading {"level":3} -->
<h3 class="wp-block-heading">1. 顶部作用域悬浮窗</h3>
<!-- /wp:heading -->

<!-- wp:paragraph -->
<p>当用户在 Hex-Rays 伪代码窗口中滚动代码时，插件会在窗口顶部显示当前代码所在的作用域链。</p>
<!-- /wp:paragraph -->

<!-- wp:paragraph -->
<p>例如当前代码位于某个 <code>if</code> 和 <code>while</code> 内部时，悬浮窗会显示类似内容：</p>
<!-- /wp:paragraph -->

<!-- wp:image {"id":1219,"sizeSlug":"large","linkDestination":"none"} -->
<figure class="wp-block-image size-large"><img src="http://39.104.51.85/wp-content/uploads/2026/04/image-140-1024x397.png" alt="" class="wp-image-1219"/></figure>
<!-- /wp:image -->

<!-- wp:paragraph -->
<p>每一行表示一层作用域，越靠下越接近当前代码位置。</p>
<!-- /wp:paragraph -->

<!-- wp:heading {"level":3} -->
<h3 class="wp-block-heading">2. 多层嵌套提示</h3>
<!-- /wp:heading -->

<!-- wp:paragraph -->
<p>插件可以同时显示多层嵌套结构，适合分析复杂函数中的深层逻辑。</p>
<!-- /wp:paragraph -->

<!-- wp:paragraph -->
<p>当代码嵌套较深时，可以通过顶部悬浮窗快速知道当前代码处于哪几层逻辑块中。</p>
<!-- /wp:paragraph -->

<!-- wp:heading {"level":3} -->
<h3 class="wp-block-heading">3. 括号匹配与高亮</h3>
<!-- /wp:heading -->

<!-- wp:paragraph -->
<p>插件会自动匹配伪代码中的 <code>{</code> 和 <code>}</code>。</p>
<!-- /wp:paragraph -->

<!-- wp:image {"id":1220,"sizeSlug":"full","linkDestination":"none"} -->
<figure class="wp-block-image size-full"><img src="http://39.104.51.85/wp-content/uploads/2026/04/image-141.png" alt="" class="wp-image-1220"/></figure>
<!-- /wp:image -->

<!-- wp:paragraph -->
<p>不同层级的括号会使用不同颜色进行标记，方便用户区分不同代码块的范围。</p>
<!-- /wp:paragraph -->

<!-- wp:heading {"level":3} -->
<h3 class="wp-block-heading">4. 左侧行号提示</h3>
<!-- /wp:heading -->

<!-- wp:paragraph -->
<p>悬浮窗左侧会显示对应代码块在伪代码中的行号。</p>
<!-- /wp:paragraph -->

<!-- wp:paragraph -->
<p>用户可以通过行号快速判断当前悬浮窗中的作用域来自原始伪代码的哪一行。</p>
<!-- /wp:paragraph -->

<!-- wp:heading {"level":3} -->
<h3 class="wp-block-heading">5. 点击悬浮窗跳转</h3>
<!-- /wp:heading -->

<!-- wp:paragraph -->
<p>用户可以点击悬浮窗中的任意一行，插件会自动跳转到该作用域在伪代码中的起始位置。</p>
<!-- /wp:paragraph -->

<!-- wp:image {"id":1221,"sizeSlug":"large","linkDestination":"none"} -->
<figure class="wp-block-image size-large"><img src="http://39.104.51.85/wp-content/uploads/2026/04/PixPin_2026-04-29_15-05-44-1024x580.gif" alt="" class="wp-image-1221"/></figure>
<!-- /wp:image -->

<!-- wp:paragraph -->
<p>这个功能适合在深层代码中快速回到外层 <code>if</code>、<code>while</code>、<code>switch</code> 或函数开头查看上下文。</p>
<!-- /wp:paragraph -->

<!-- wp:heading {"level":3} -->
<h3 class="wp-block-heading">6. 跳转位置自动避开悬浮窗</h3>
<!-- /wp:heading -->

<!-- wp:paragraph -->
<p>点击悬浮窗跳转后，目标代码不会被顶部悬浮窗遮挡。</p>
<!-- /wp:paragraph -->

<!-- wp:paragraph -->
<p>插件会自动把目标代码显示在悬浮窗下方，保证跳转后能直接看到目标行。</p>
<!-- /wp:paragraph -->

<!-- wp:heading {"level":3} -->
<h3 class="wp-block-heading">7. 按 b 返回跳转前位置</h3>
<!-- /wp:heading -->

<!-- wp:paragraph -->
<p>每次通过悬浮窗跳转前，插件会记录跳转前的位置。</p>
<!-- /wp:paragraph -->

<!-- wp:paragraph -->
<p>跳转后按键盘上的：</p>
<!-- /wp:paragraph -->

<!-- wp:preformatted -->
<pre class="wp-block-preformatted">“b”</pre>
<!-- /wp:preformatted -->

<!-- wp:paragraph -->
<p>即可返回上一次跳转前的位置。</p>
<!-- /wp:paragraph -->

<!-- wp:paragraph -->
<p>如果连续跳转多次，可以连续按 <code>b</code> 逐步返回。</p>
<!-- /wp:paragraph -->

<!-- wp:paragraph -->
<p>回溯记录最多保存 10 次。</p>
<!-- /wp:paragraph -->

<!-- wp:image {"id":1222,"sizeSlug":"large","linkDestination":"none"} -->
<figure class="wp-block-image size-large"><img src="http://39.104.51.85/wp-content/uploads/2026/04/PixPin_2026-04-29_15-06-53-1024x523.gif" alt="" class="wp-image-1222"/></figure>
<!-- /wp:image -->

<!-- wp:heading -->
<h2 class="wp-block-heading">安装方法</h2>
<!-- /wp:heading -->

<!-- wp:heading {"level":3} -->
<h3 class="wp-block-heading">1. 准备插件文件</h3>
<!-- /wp:heading -->

<!-- wp:paragraph -->
<p>将插件文件放入 IDA 安装目录下的插件目录：</p>
<!-- /wp:paragraph -->

<!-- wp:preformatted -->
<pre class="wp-block-preformatted">IDA安装目录\plugins\</pre>
<!-- /wp:preformatted -->

<!-- wp:paragraph -->
<p>放入插件后，完全关闭 IDA，然后重新打开。</p>
<!-- /wp:paragraph -->

<!-- wp:paragraph -->
<p>打开 Hex-Rays 伪代码窗口后，插件会自动启用。</p>
<!-- /wp:paragraph -->

<!-- wp:heading -->
<h2 class="wp-block-heading">使用方法</h2>
<!-- /wp:heading -->

<!-- wp:heading {"level":3} -->
<h3 class="wp-block-heading">查看当前代码所在作用域</h3>
<!-- /wp:heading -->

<!-- wp:list {"ordered":true} -->
<ol class="wp-block-list"><!-- wp:list-item -->
<li>打开 IDA。</li>
<!-- /wp:list-item -->

<!-- wp:list-item -->
<li>打开某个函数的 Hex-Rays 伪代码视图。</li>
<!-- /wp:list-item -->

<!-- wp:list-item -->
<li>向下滚动代码。</li>
<!-- /wp:list-item -->

<!-- wp:list-item -->
<li>查看窗口顶部的悬浮窗。</li>
<!-- /wp:list-item -->

<!-- wp:list-item -->
<li>悬浮窗中显示的内容就是当前代码所在的多层作用域。</li>
<!-- /wp:list-item --></ol>
<!-- /wp:list -->

<!-- wp:heading {"level":3} -->
<h3 class="wp-block-heading">跳转到某个作用域开头</h3>
<!-- /wp:heading -->

<!-- wp:list {"ordered":true} -->
<ol class="wp-block-list"><!-- wp:list-item -->
<li>在顶部悬浮窗中找到想查看的作用域。</li>
<!-- /wp:list-item -->

<!-- wp:list-item -->
<li>用鼠标点击该行。</li>
<!-- /wp:list-item -->

<!-- wp:list-item -->
<li>伪代码窗口会自动跳转到该作用域对应的起始位置。</li>
<!-- /wp:list-item -->

<!-- wp:list-item -->
<li>跳转后的目标代码会显示在悬浮窗下方。</li>
<!-- /wp:list-item --></ol>
<!-- /wp:list -->

<!-- wp:heading {"level":3} -->
<h3 class="wp-block-heading">返回跳转前位置</h3>
<!-- /wp:heading -->

<!-- wp:list {"ordered":true} -->
<ol class="wp-block-list"><!-- wp:list-item -->
<li>点击悬浮窗完成跳转。</li>
<!-- /wp:list-item -->

<!-- wp:list-item -->
<li>阅读完目标位置后，按键盘上的 <code>b</code>。</li>
<!-- /wp:list-item -->

<!-- wp:list-item -->
<li>伪代码窗口会回到上一次跳转前的位置。</li>
<!-- /wp:list-item --></ol>
<!-- /wp:list -->

<!-- wp:paragraph -->
<p>如果按 <code>b</code> 没有反应，可以先点击一下 Hex-Rays 伪代码正文区域，再按 <code>b</code>。</p>
<!-- /wp:paragraph -->

<!-- wp:heading -->
<h2 class="wp-block-heading">常见问题</h2>
<!-- /wp:heading -->

<!-- wp:heading {"level":3} -->
<h3 class="wp-block-heading">插件没有自动加载</h3>
<!-- /wp:heading -->

<!-- wp:paragraph -->
<p>请检查：<br>插件是否放入正确的 plugins 目录<br>IDA 是否已经完全重启</p>
<!-- /wp:paragraph -->

<!-- wp:heading {"level":3} -->
<h3 class="wp-block-heading">悬浮窗没有显示</h3>
<!-- /wp:heading -->

<!-- wp:paragraph -->
<p>请检查：</p>
<!-- /wp:paragraph -->

<!-- wp:preformatted -->
<pre class="wp-block-preformatted">当前窗口是否是 Hex-Rays 伪代码窗口（光标需要定位在伪代码窗口）<br>当前代码位置是否处于花括号作用域内部<br>是否已经滚动到较深的代码位置</pre>
<!-- /wp:preformatted -->

<!-- wp:paragraph -->
<p>可以尝试刷新伪代码视图或重新打开函数。</p>
<!-- /wp:paragraph -->

<!-- wp:heading {"level":3} -->
<h3 class="wp-block-heading">按 b 没有返回</h3>
<!-- /wp:heading -->

<!-- wp:paragraph -->
<p>请确认之前已经通过点击悬浮窗发生过跳转。</p>
<!-- /wp:paragraph -->

<!-- wp:paragraph -->
<p>如果仍然没有反应，先点击一下 Hex-Rays 伪代码正文区域，让键盘焦点回到伪代码窗口，然后再按 <code>b</code>。</p>
<!-- /wp:paragraph -->

<!-- wp:heading -->
<h2 class="wp-block-heading">功能总结</h2>
<!-- /wp:heading -->

<!-- wp:paragraph -->
<p><code>scope_match</code> 主要提供以下能力：</p>
<!-- /wp:paragraph -->

<!-- wp:preformatted -->
<pre class="wp-block-preformatted">显示当前代码所在作用域<br>显示多层嵌套结构<br>自动匹配并高亮花括号<br>覆盖显示对应行号<br>点击悬浮窗跳转到作用域开头<br>跳转后自动避开悬浮窗遮挡<br>按 b 返回跳转前位置</pre>
<!-- /wp:preformatted -->

<!-- wp:paragraph -->
<p>它适合在分析复杂反编译伪代码时作为辅助阅读工具使用。</p>
<!-- /wp:paragraph -->
