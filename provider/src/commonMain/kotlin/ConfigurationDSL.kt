package at.asitplus.crypto.provider

object DSL {
    fun <S: DSL.Data, T: S> resolve(factory: ()->T, config: (S.()->Unit)?): T =
        (if (config == null) factory() else factory().apply(config)).also(DSL.Data::validate)

    sealed interface Holder<out T> {
        val v: T
    }

    sealed interface Invokable<out Storage, out Target: Storage&Any>: Holder<Storage> {
        operator fun invoke(config: Target.()->Unit)
    }

    class DirectHolder<out T: DSL.Data?> constructor (default: T, private val factory: ()->(T & Any))
        : Invokable<T,T&Any> {
        private var _v: T = default
        override val v: T get() = _v

        override operator fun invoke(config: (T & Any).()->Unit) { _v = resolve(factory, config) }
    }
    class Generalized<out T: DSL.Data?> constructor(default: T): Holder<T> {
        private var _v: T = default
        override val v: T get() = _v
        inner class option<out S:T&Any> constructor(private val factory: ()->S) : Invokable<T,S> {
            override val v: T get() = this@Generalized.v
            override operator fun invoke(config: S.()->Unit) { _v = resolve(factory, config) }
        }
    }

    @DslMarker
    annotation class Marker

    @DSL.Marker
    open class Data {
        protected fun <T: DSL.Data> child(factory: ()->T): Invokable<T,T> =
            DirectHolder<T>(factory(), factory)
        protected fun <T: DSL.Data> childOrNull(factory: ()->T): Invokable<T?,T> =
            DirectHolder<T?>(null, factory)
        protected fun <T: DSL.Data> subclassOf(): Generalized<T?> =
            Generalized<T?>(null)
        protected fun <T: DSL.Data> subclassOf(default: T): Generalized<T> =
            Generalized<T>(default)

        internal open fun validate() {}
    }
}
